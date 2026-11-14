//! Current-user interactive logon task: supports a requireAdministrator EXE
//! without storing a Windows password or running the GUI as SYSTEM.
use std::sync::Mutex;
use tauri_plugin_autostart::ManagerExt;
use windows::{
    Win32::{
        Foundation::{CloseHandle, HANDLE, HLOCAL, LocalFree},
        Security::{
            Authorization::ConvertSidToStringSidW, GetTokenInformation, TOKEN_QUERY, TOKEN_USER,
            TokenUser,
        },
        System::{
            Com::{
                CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED, CoCreateInstance, CoInitializeEx,
                CoUninitialize,
            },
            TaskScheduler::{
                ITaskFolder, ITaskService, TASK_CREATE_OR_UPDATE, TASK_LOGON_INTERACTIVE_TOKEN,
                TaskScheduler,
            },
            Threading::{GetCurrentProcess, OpenProcessToken},
            Variant::VARIANT,
        },
    },
    core::{BSTR, PWSTR},
};

static OPERATION: Mutex<()> = Mutex::new(());
fn error(operation: &str, error: windows::core::Error) -> String {
    format!(
        "Windows 计划任务 {operation} 失败：{} (0x{:08x})",
        error.message(),
        error.code().0 as u32
    )
}
struct Token(HANDLE);
impl Drop for Token {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseHandle(self.0);
        }
    }
}
struct Com(bool);
impl Drop for Com {
    fn drop(&mut self) {
        if self.0 {
            unsafe {
                CoUninitialize();
            }
        }
    }
}

fn current_sid() -> Result<String, String> {
    unsafe {
        let mut token = HANDLE::default();
        OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token)
            .map_err(|e| error("读取当前用户", e))?;
        let token = Token(token);
        let mut size = 0;
        let _ = GetTokenInformation(token.0, TokenUser, None, 0, &mut size);
        if size == 0 {
            return Err("无法读取当前 Windows 用户 SID".into());
        }
        let mut buffer = vec![0usize; (size as usize).div_ceil(std::mem::size_of::<usize>())];
        GetTokenInformation(
            token.0,
            TokenUser,
            Some(buffer.as_mut_ptr().cast()),
            size,
            &mut size,
        )
        .map_err(|e| error("读取当前用户", e))?;
        let user = &*buffer.as_ptr().cast::<TOKEN_USER>();
        let mut sid = PWSTR::null();
        ConvertSidToStringSidW(user.User.Sid, &mut sid)
            .map_err(|e| error("转换当前用户 SID", e))?;
        let text = sid
            .to_string()
            .map_err(|_| "Windows 用户 SID 编码无效".to_string());
        LocalFree(Some(HLOCAL(sid.0.cast())));
        text
    }
}
fn with_folder<T>(
    operation: impl FnOnce(&ITaskFolder, &BSTR, &str) -> Result<T, String>,
) -> Result<T, String> {
    let initialized = unsafe { CoInitializeEx(None, COINIT_MULTITHREADED) };
    if initialized.is_err() && initialized.0 as u32 != 0x80010106 {
        return Err(error(
            "初始化 COM",
            windows::core::Error::from_hresult(initialized),
        ));
    }
    let _com = Com(initialized.is_ok());
    let sid = current_sid()?;
    let service: ITaskService =
        unsafe { CoCreateInstance(&TaskScheduler, None, CLSCTX_INPROC_SERVER) }
            .map_err(|e| error("打开服务", e))?;
    let empty = VARIANT::default();
    unsafe { service.Connect(&empty, &empty, &empty, &empty) }.map_err(|e| error("连接服务", e))?;
    let folder =
        unsafe { service.GetFolder(&BSTR::from("\\")) }.map_err(|e| error("打开目录", e))?;
    operation(&folder, &BSTR::from(format!("ArrayConnect-{sid}")), &sid)
}
fn enabled(folder: &ITaskFolder, name: &BSTR) -> Result<bool, String> {
    match unsafe { folder.GetTask(name) } {
        Ok(task) => unsafe { task.Enabled() }
            .map(|enabled| enabled.as_bool())
            .map_err(|e| error("读取状态", e)),
        Err(e) if matches!(e.code().0 as u32, 0x80070002 | 0x80070003) => Ok(false),
        Err(e) => Err(error("读取状态", e)),
    }
}
fn remove(folder: &ITaskFolder, name: &BSTR) -> Result<(), String> {
    match unsafe { folder.DeleteTask(name, 0) } {
        Ok(()) => Ok(()),
        Err(e) if matches!(e.code().0 as u32, 0x80070002 | 0x80070003) => Ok(()),
        Err(e) => Err(error("移除", e)),
    }
}
fn register(folder: &ITaskFolder, name: &BSTR, sid: &str) -> Result<(), String> {
    let executable = std::env::current_exe().map_err(|_| "无法确定应用路径")?;
    let parent = executable.parent().ok_or("无法确定应用目录")?;
    let xml = task_xml(
        &executable.to_string_lossy(),
        &parent.to_string_lossy(),
        sid,
    );
    let empty = VARIANT::default();
    unsafe {
        folder.RegisterTask(
            name,
            &BSTR::from(xml),
            TASK_CREATE_OR_UPDATE.0,
            &empty,
            &empty,
            TASK_LOGON_INTERACTIVE_TOKEN,
            &empty,
        )
    }
    .map_err(|e| error("注册", e))?;
    Ok(())
}
pub fn is_enabled(app: &tauri::AppHandle) -> Result<bool, String> {
    let _operation = OPERATION.lock().unwrap();
    with_folder(|folder, name, sid| {
        let enabled = enabled(folder, name)?;
        // Preserve an existing user choice when migrating from the old Run key.
        if app
            .autolaunch()
            .is_enabled()
            .map_err(|_| "旧自启设置读取失败")?
        {
            if !enabled {
                register(folder, name, sid)?;
            }
            if app.autolaunch().disable().is_err() {
                if !enabled {
                    let _ = remove(folder, name);
                }
                return Err("旧自启项迁移失败，未更改原有启动设置".into());
            }
            return Ok(true);
        }
        Ok(enabled)
    })
}
pub fn set_enabled(app: &tauri::AppHandle, should_enable: bool) -> Result<bool, String> {
    let _operation = OPERATION.lock().unwrap();
    with_folder(|folder, name, sid| {
        if should_enable {
            register(folder, name, sid)?;
        } else {
            remove(folder, name)?;
        }
        app.autolaunch().disable().map_err(|_| "旧自启项移除失败")?;
        enabled(folder, name)
    })
}
fn xml_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}
fn task_xml(executable: &str, directory: &str, sid: &str) -> String {
    let executable = xml_escape(executable);
    let directory = xml_escape(directory);
    let sid = xml_escape(sid);
    format!(
        r#"<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
<RegistrationInfo><Description>Start Array Connect at current-user logon.</Description></RegistrationInfo>
<Triggers><LogonTrigger><Enabled>true</Enabled><UserId>{sid}</UserId></LogonTrigger></Triggers>
<Principals><Principal id="User"><UserId>{sid}</UserId><LogonType>InteractiveToken</LogonType><RunLevel>HighestAvailable</RunLevel></Principal></Principals>
<Settings><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy><DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries><StopIfGoingOnBatteries>false</StopIfGoingOnBatteries><AllowHardTerminate>false</AllowHardTerminate><StartWhenAvailable>true</StartWhenAvailable><ExecutionTimeLimit>PT0S</ExecutionTimeLimit></Settings>
<Actions Context="User"><Exec><Command>{executable}</Command><WorkingDirectory>{directory}</WorkingDirectory></Exec></Actions>
</Task>"#
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn startup_task_is_interactive_scoped_to_user_and_escapes_paths() {
        let xml = task_xml(
            r#"C:\Apps & Tools\Array Connect.exe"#,
            r#"C:\Apps & Tools"#,
            "S-1-5-21-test",
        );
        assert!(xml.contains("Apps &amp; Tools"));
        assert!(xml.contains("<LogonType>InteractiveToken</LogonType>"));
        assert!(xml.contains("<RunLevel>HighestAvailable</RunLevel>"));
        assert_eq!(xml.matches("<UserId>S-1-5-21-test</UserId>").count(), 2);
        assert!(xml.contains("<ExecutionTimeLimit>PT0S</ExecutionTimeLimit>"));
        assert!(!xml.contains("Password"));
    }

    #[test]
    #[ignore = "local read-only Windows Task Scheduler XML validation"]
    fn windows_accepts_the_task_definition_without_registering_it() {
        with_folder(|_, _, sid| {
            let service: ITaskService =
                unsafe { CoCreateInstance(&TaskScheduler, None, CLSCTX_INPROC_SERVER) }
                    .map_err(|e| error("创建验证对象", e))?;
            let empty = VARIANT::default();
            unsafe { service.Connect(&empty, &empty, &empty, &empty) }
                .map_err(|e| error("连接验证对象", e))?;
            let definition = unsafe { service.NewTask(0) }.map_err(|e| error("创建内存定义", e))?;
            let xml = task_xml(
                r"C:\Apps & Tools\Array Connect.exe",
                r"C:\Apps & Tools",
                sid,
            );
            unsafe { definition.SetXmlText(&BSTR::from(xml)) }
                .map_err(|e| error("验证任务 XML", e))?;
            Ok(())
        })
        .unwrap();
    }
}
