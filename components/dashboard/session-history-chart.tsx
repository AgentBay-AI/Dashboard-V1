"use client"

import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Legend } from "recharts"

export function SessionHistoryChart() {
  const data = [
    { date: "Feb 17", success: 2, indeterminate: 1, fail: 0 },
    { date: "Feb 19", success: 5, indeterminate: 2, fail: 1 },
    { date: "Feb 22", success: 8, indeterminate: 3, fail: 2 },
    { date: "Feb 24", success: 6, indeterminate: 4, fail: 1 },
    { date: "Feb 26", success: 9, indeterminate: 5, fail: 3 },
    { date: "Mar 2", success: 15, indeterminate: 6, fail: 4 },
    { date: "Mar 4", success: 18, indeterminate: 4, fail: 2 },
    { date: "Mar 6", success: 16, indeterminate: 3, fail: 1 },
  ]

  return (
    <Card>
      <CardHeader>
        <CardTitle>Session History</CardTitle>
        <CardDescription>Session outcomes over time</CardDescription>
      </CardHeader>
      <CardContent>
        <div className="h-[200px]">
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
              <XAxis dataKey="date" tick={{ fontSize: 12 }} tickLine={false} axisLine={false} />
              <YAxis tick={{ fontSize: 12 }} tickLine={false} axisLine={false} />
              <Tooltip
                contentStyle={{
                  backgroundColor: "hsl(var(--background))",
                  borderColor: "hsl(var(--border))",
                  borderRadius: "0.5rem",
                  boxShadow: "0 1px 3px 0 rgb(0 0 0 / 0.1), 0 1px 2px -1px rgb(0 0 0 / 0.1)",
                }}
                itemStyle={{ color: "hsl(var(--foreground))" }}
                labelStyle={{ color: "hsl(var(--foreground))" }}
              />
              <Legend />
              <Line
                type="monotone"
                dataKey="success"
                stroke="#3730a3"
                strokeWidth={2}
                dot={{ r: 3, strokeWidth: 2 }}
                activeDot={{ r: 5, strokeWidth: 2 }}
              />
              <Line
                type="monotone"
                dataKey="indeterminate"
                stroke="#06b6d4"
                strokeWidth={2}
                dot={{ r: 3, strokeWidth: 2 }}
                activeDot={{ r: 5, strokeWidth: 2 }}
              />
              <Line
                type="monotone"
                dataKey="fail"
                stroke="#e11d48"
                strokeWidth={2}
                dot={{ r: 3, strokeWidth: 2 }}
                activeDot={{ r: 5, strokeWidth: 2 }}
              />
            </LineChart>
          </ResponsiveContainer>
        </div>
      </CardContent>
    </Card>
  )
}
