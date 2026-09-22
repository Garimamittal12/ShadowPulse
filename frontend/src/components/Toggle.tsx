interface ToggleProps {
  checked: boolean;
  onChange: () => void;
  label?: string;
}

export function Toggle({ checked, onChange, label }: ToggleProps) {
  return (
    <button
      role="switch"
      aria-checked={checked}
      aria-label={label}
      onClick={onChange}
      className={`
        relative inline-flex items-center flex-shrink-0
        w-[52px] h-[30px] rounded-full
        transition-colors duration-200 ease-in-out
        focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500 focus-visible:ring-offset-2
        ${checked ? 'bg-[#2196F3]' : 'bg-[#C8CDD6]'}
      `}
    >
      <span
        className={`
          absolute top-[3px]
          w-6 h-6 rounded-full bg-white
          shadow-[0_2px_6px_rgba(0,0,0,0.25)]
          transition-transform duration-200 ease-in-out
          ${checked ? 'translate-x-[23px]' : 'translate-x-[3px]'}
        `}
      />
    </button>
  );
}
