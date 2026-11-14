use crate::{Result, VpnError, client::Shared};
use std::{future::Future, time::Duration};
use tokio::time::timeout;

pub(crate) async fn bounded<T>(
    shared: &Shared,
    duration: Duration,
    label: &'static str,
    future: impl Future<Output = Result<T>>,
) -> Result<T> {
    tokio::select! {biased;_=shared.cancel.cancelled()=>Err(VpnError::Cancelled),
    result=timeout(duration,future)=>result.map_err(|_|VpnError::Timeout(label))?}
}
