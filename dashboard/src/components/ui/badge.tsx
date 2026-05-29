import * as React from "react";
import { cva, type VariantProps } from "class-variance-authority";
import { cn } from "@/lib/utils";

const badgeVariants = cva(
  "inline-flex items-center rounded-full border px-2.5 py-0.5 text-xs font-semibold transition-colors focus:outline-none focus:ring-2 focus:ring-ring focus:ring-offset-2",
  {
    variants: {
      variant: {
        default: "border-transparent bg-primary text-primary-foreground",
        secondary: "border-transparent bg-secondary text-secondary-foreground",
        destructive: "border-transparent bg-destructive text-destructive-foreground",
        outline: "text-foreground",
        critical: "border-transparent bg-severity-critical/15 text-severity-critical hover:bg-severity-critical/25",
        high: "border-transparent bg-severity-high/15 text-severity-high hover:bg-severity-high/25",
        medium: "border-transparent bg-severity-medium/15 text-severity-medium hover:bg-severity-medium/25",
        low: "border-transparent bg-severity-low/15 text-severity-low hover:bg-severity-low/25",
        info: "border-transparent bg-severity-info/15 text-severity-info hover:bg-severity-info/25",
      },
    },
    defaultVariants: { variant: "default" },
  },
);

export interface BadgeProps
  extends React.HTMLAttributes<HTMLDivElement>,
    VariantProps<typeof badgeVariants> {}

function Badge({ className, variant, ...props }: BadgeProps) {
  return <div className={cn(badgeVariants({ variant }), className)} {...props} />;
}

export { Badge, badgeVariants };
