import { useId, type ReactNode } from "react";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";

export function TextField({
  label,
  hint,
  value,
  onChange,
  type = "text",
  placeholder,
  disabled,
  autoComplete = "off",
}: {
  label: string;
  hint?: string;
  value: string | number;
  onChange: (value: string) => void;
  type?: string;
  placeholder?: string;
  disabled?: boolean;
  autoComplete?: string;
}) {
  const id = useId();
  return (
    <div className="field">
      <Label htmlFor={id}>{label}</Label>
      <Input
        id={id}
        type={type}
        value={value}
        onChange={(event) => onChange(event.target.value)}
        placeholder={placeholder}
        disabled={disabled}
        autoComplete={autoComplete}
        spellCheck={false}
      />
      {hint && <p className="field-hint">{hint}</p>}
    </div>
  );
}
export function Choice({
  label,
  value,
  onChange,
  options,
  hint,
}: {
  label: string;
  value: string;
  onChange: (value: string) => void;
  options: [string, string][];
  hint?: string;
}) {
  const id = useId();
  return (
    <div className="field">
      <Label htmlFor={id}>{label}</Label>
      <Select value={value} onValueChange={onChange}>
        <SelectTrigger id={id} className="w-full">
          <SelectValue />
        </SelectTrigger>
        <SelectContent>
          {options.map(([key, text]) => (
            <SelectItem key={key} value={key}>
              {text}
            </SelectItem>
          ))}
        </SelectContent>
      </Select>
      {hint && <p className="field-hint">{hint}</p>}
    </div>
  );
}
export function ToggleRow({
  label,
  hint,
  checked,
  onChange,
  disabled,
  icon,
}: {
  label: string;
  hint?: string;
  checked: boolean;
  onChange: (value: boolean) => void;
  disabled?: boolean;
  icon?: ReactNode;
}) {
  const id = useId();
  return (
    <div className="toggle-row">
      {icon && <span className="setting-icon">{icon}</span>}
      <div className="toggle-description">
        <Label htmlFor={id}>{label}</Label>
        {hint && <p>{hint}</p>}
      </div>
      <Switch
        id={id}
        checked={checked}
        onCheckedChange={onChange}
        disabled={disabled}
      />
    </div>
  );
}
