import { cn } from "@/lib/utils"

interface LoadingSkeletonProps {
  className?: string
  lines?: number
  height?: string
}

export function LoadingSkeleton({ className, lines = 1, height = "h-4" }: LoadingSkeletonProps) {
  return (
    <div className={cn("space-y-2", className)}>
      {Array.from({ length: lines }).map((_, index) => (
        <div
          key={index}
          className={cn(
            "bg-muted rounded animate-pulse",
            height,
            index === 0 ? "w-full" : index === 1 ? "w-3/4" : "w-1/2"
          )}
        />
      ))}
    </div>
  )
}

interface MetricCardSkeletonProps {
  className?: string
}

export function MetricCardSkeleton({ className }: MetricCardSkeletonProps) {
  return (
    <div className={cn("p-4", className)}>
      <div className="flex items-center justify-between">
        <div className="flex-1">
          <div className="h-4 bg-muted rounded animate-pulse mb-2" />
          <div className="h-6 bg-muted rounded animate-pulse w-20" />
          <div className="h-3 bg-muted rounded animate-pulse w-16 mt-2" />
        </div>
        <div className="p-2 rounded-lg bg-muted/50 ml-3">
          <div className="h-5 w-5 bg-muted rounded animate-pulse" />
        </div>
      </div>
    </div>
  )
}

interface ActivitySkeletonProps {
  className?: string
}

export function ActivitySkeleton({ className }: ActivitySkeletonProps) {
  return (
    <div className={cn("flex items-start space-x-3 p-2 rounded-lg", className)}>
      <div className="p-1.5 rounded-lg bg-muted">
        <div className="h-3 w-3 bg-muted-foreground/30 rounded animate-pulse" />
      </div>
      <div className="flex-1 min-w-0">
        <div className="h-4 bg-muted rounded animate-pulse mb-1" />
        <div className="h-3 bg-muted rounded animate-pulse w-3/4 mt-1" />
        <div className="h-3 bg-muted rounded animate-pulse w-1/2 mt-1" />
      </div>
    </div>
  )
} 