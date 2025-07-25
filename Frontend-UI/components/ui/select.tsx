"use client"

import * as React from "react"
import { cn } from "@/lib/utils"

// Temporary icon replacements
const Check = ({ className }: { className?: string }) => <div className={`${className}`}>✓</div>
const ChevronDown = ({ className }: { className?: string }) => <div className={`${className}`}>▼</div>
const ChevronUp = ({ className }: { className?: string }) => <div className={`${className}`}>▲</div>

// Simplified Select components without Radix UI dependency
const Select = ({ children, value, onValueChange, ...props }: any) => {
  return <div className="relative" {...props}>{children}</div>
}

const SelectGroup = ({ children, ...props }: any) => {
  return <div {...props}>{children}</div>
}

const SelectValue = ({ placeholder, children, ...props }: any) => {
  return <span {...props}>{children || placeholder}</span>
}

const SelectTrigger = React.forwardRef<HTMLButtonElement, any>(
  ({ className, children, ...props }, ref) => (
    <button
    ref={ref}
      type="button"
    className={cn(
      "flex h-10 w-full items-center justify-between rounded-md border border-input bg-background px-3 py-2 text-sm ring-offset-background placeholder:text-muted-foreground focus:outline-none focus:ring-2 focus:ring-ring focus:ring-offset-2 disabled:cursor-not-allowed disabled:opacity-50 [&>span]:line-clamp-1",
      className
    )}
    {...props}
  >
    {children}
      <ChevronDown className="h-4 w-4 opacity-50" />
    </button>
  )
)
SelectTrigger.displayName = "SelectTrigger"

const SelectScrollUpButton = React.forwardRef<HTMLDivElement, any>(
  ({ className, ...props }, ref) => (
    <div
    ref={ref}
      className={cn("flex cursor-default items-center justify-center py-1", className)}
    {...props}
  >
    <ChevronUp className="h-4 w-4" />
    </div>
  )
)
SelectScrollUpButton.displayName = "SelectScrollUpButton"

const SelectScrollDownButton = React.forwardRef<HTMLDivElement, any>(
  ({ className, ...props }, ref) => (
    <div
    ref={ref}
      className={cn("flex cursor-default items-center justify-center py-1", className)}
    {...props}
  >
    <ChevronDown className="h-4 w-4" />
    </div>
  )
)
SelectScrollDownButton.displayName = "SelectScrollDownButton"

const SelectContent = React.forwardRef<HTMLDivElement, any>(
  ({ className, children, position = "popper", ...props }, ref) => (
    <div
      ref={ref}
      className={cn(
        "relative z-50 max-h-96 min-w-[8rem] overflow-hidden rounded-md border bg-popover text-popover-foreground shadow-md",
        className
      )}
      {...props}
    >
      <SelectScrollUpButton />
      <div className="p-1">
        {children}
      </div>
      <SelectScrollDownButton />
    </div>
  )
)
SelectContent.displayName = "SelectContent"

const SelectLabel = React.forwardRef<HTMLDivElement, any>(
  ({ className, ...props }, ref) => (
    <div
    ref={ref}
    className={cn("py-1.5 pl-8 pr-2 text-sm font-semibold", className)}
    {...props}
  />
  )
)
SelectLabel.displayName = "SelectLabel"

const SelectItem = React.forwardRef<HTMLDivElement, any>(
  ({ className, children, value, onSelect, ...props }, ref) => (
    <div
    ref={ref}
    className={cn(
      "relative flex w-full cursor-default select-none items-center rounded-sm py-1.5 pl-8 pr-2 text-sm outline-none focus:bg-accent focus:text-accent-foreground data-[disabled]:pointer-events-none data-[disabled]:opacity-50",
      className
    )}
      onClick={() => onSelect?.(value)}
    {...props}
  >
    <span className="absolute left-2 flex h-3.5 w-3.5 items-center justify-center">
        <Check className="h-4 w-4" />
    </span>
      <span>{children}</span>
    </div>
  )
)
SelectItem.displayName = "SelectItem"

const SelectSeparator = React.forwardRef<HTMLDivElement, any>(
  ({ className, ...props }, ref) => (
    <div
    ref={ref}
    className={cn("-mx-1 my-1 h-px bg-muted", className)}
    {...props}
  />
  )
)
SelectSeparator.displayName = "SelectSeparator"

export {
  Select,
  SelectGroup,
  SelectValue,
  SelectTrigger,
  SelectContent,
  SelectLabel,
  SelectItem,
  SelectSeparator,
  SelectScrollUpButton,
  SelectScrollDownButton,
}
