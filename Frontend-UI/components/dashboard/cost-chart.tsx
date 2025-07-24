"use client"

import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from "recharts"

export function CostChart() {
  const data = [
    { week: "Week 1", cost: 280 },
    { week: "Week 2", cost: 350 },
    { week: "Week 3", cost: 310 },
    { week: "Week 4", cost: 310 },
  ]

  return (
    <div className="h-[200px] mt-4">
      <ResponsiveContainer width="100%" height="100%">
        <LineChart
          data={data}
          margin={{
            top: 5,
            right: 10,
            left: 0,
            bottom: 5,
          }}
        >
          <CartesianGrid strokeDasharray="3 3" opacity={0.2} />
          <XAxis dataKey="week" tick={{ fontSize: 12 }} tickLine={false} axisLine={false} />
          <YAxis tick={{ fontSize: 12 }} tickLine={false} axisLine={false} hide />
          <Tooltip
            contentStyle={{
              backgroundColor: "hsl(var(--background))",
              borderColor: "hsl(var(--border))",
              borderRadius: "0.5rem",
              boxShadow: "0 1px 3px 0 rgb(0 0 0 / 0.1), 0 1px 2px -1px rgb(0 0 0 / 0.1)",
            }}
            itemStyle={{ color: "hsl(var(--foreground))" }}
            labelStyle={{ color: "hsl(var(--foreground))" }}
            formatter={(value) => [`$${value}`, "Cost"]}
          />
          <Line type="monotone" dataKey="cost" stroke="hsl(var(--primary))" strokeWidth={2} dot={false} />
        </LineChart>
      </ResponsiveContainer>
    </div>
  )
}
