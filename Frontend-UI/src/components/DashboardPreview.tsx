import { useState, useEffect } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Progress } from "@/components/ui/progress";
import { Badge } from "@/components/ui/badge";
import { 
  TrendingUp, 
  Users, 
  DollarSign, 
  Activity,
  Shield,
  Cpu,
  AlertCircle,
  CheckCircle
} from "lucide-react";

const DashboardPreview = () => {
  const [animatedValues, setAnimatedValues] = useState({
    activeAgents: 0,
    successRate: 0,
    monthlyCost: 0,
    systemHealth: 0,
    cpuUsage: 0,
    memoryUsage: 0
  });

  const targetValues = {
    activeAgents: 12,
    successRate: 94.2,
    monthlyCost: 1247.50,
    systemHealth: 99.9,
    cpuUsage: 68,
    memoryUsage: 74
  };

  useEffect(() => {
    const animateValues = () => {
      const duration = 2000; // 2 seconds
      const startTime = Date.now();

      const animate = () => {
        const elapsed = Date.now() - startTime;
        const progress = Math.min(elapsed / duration, 1);
        
        // Easing function
        const easeOutCubic = (t: number) => 1 - Math.pow(1 - t, 3);
        const easedProgress = easeOutCubic(progress);

        setAnimatedValues({
          activeAgents: Math.floor(targetValues.activeAgents * easedProgress),
          successRate: Number((targetValues.successRate * easedProgress).toFixed(1)),
          monthlyCost: Number((targetValues.monthlyCost * easedProgress).toFixed(2)),
          systemHealth: Number((targetValues.systemHealth * easedProgress).toFixed(1)),
          cpuUsage: Math.floor(targetValues.cpuUsage * easedProgress),
          memoryUsage: Math.floor(targetValues.memoryUsage * easedProgress)
        });

        if (progress < 1) {
          requestAnimationFrame(animate);
        }
      };

      animate();
    };

    // Start animation after a small delay
    const timer = setTimeout(animateValues, 500);
    return () => clearTimeout(timer);
  }, []);

  const [hoveredCard, setHoveredCard] = useState<string | null>(null);

  const cards = [
    {
      id: "agents",
      title: "Active Agents",
      value: animatedValues.activeAgents,
      subtitle: "of 25 total agents",
      icon: Users,
      color: "text-info",
      progress: (animatedValues.activeAgents / 25) * 100,
      details: "12 agents currently handling sessions with 94.2% success rate"
    },
    {
      id: "success",
      title: "Success Rate",
      value: `${animatedValues.successRate}%`,
      subtitle: "+0.0% from last week",
      icon: TrendingUp,
      color: "text-success",
      progress: animatedValues.successRate,
      details: "Excellent performance with consistent improvement over time"
    },
    {
      id: "cost",
      title: "Monthly Cost",
      value: `$${animatedValues.monthlyCost}`,
      subtitle: "$49.90/agent",
      icon: DollarSign,
      color: "text-warning",
      progress: 60,
      details: "Cost breakdown: 65% tokens, 25% infrastructure, 10% monitoring"
    },
    {
      id: "health",
      title: "System Health",
      value: `${animatedValues.systemHealth}%`,
      subtitle: "Excellent uptime",
      icon: Activity,
      color: "text-success",
      progress: animatedValues.systemHealth,
      details: `CPU: ${animatedValues.cpuUsage}%, Memory: ${animatedValues.memoryUsage}%, Storage: 45%`
    }
  ];

  const securityAlerts = [
    { type: "success", message: "PII detection active", time: "2 min ago" },
    { type: "warning", message: "Rate limit reached", time: "5 min ago" },
    { type: "info", message: "Compliance check passed", time: "12 min ago" }
  ];

  return (
    <div className="w-full max-w-4xl mx-auto space-y-6 animate-fade-in">
      {/* Main Metrics Grid */}
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        {cards.map((card, index) => {
          const Icon = card.icon;
          return (
            <Card 
              key={card.id}
              className="relative overflow-hidden transition-all duration-300 hover:scale-105 hover:shadow-lg cursor-pointer"
              style={{ animationDelay: `${index * 0.1}s` }}
              onMouseEnter={() => setHoveredCard(card.id)}
              onMouseLeave={() => setHoveredCard(null)}
            >
              <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                <CardTitle className="text-sm font-medium">{card.title}</CardTitle>
                <Icon className={`h-4 w-4 ${card.color}`} />
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold">{card.value}</div>
                <p className="text-xs text-muted-foreground">{card.subtitle}</p>
                <Progress 
                  value={card.progress} 
                  className="mt-2 transition-all duration-1000" 
                />
                
                {/* Tooltip */}
                {hoveredCard === card.id && (
                  <div className="absolute top-full left-1/2 transform -translate-x-1/2 mt-2 p-2 bg-popover border rounded-md shadow-lg z-10 w-64 animate-fade-in">
                    <p className="text-xs">{card.details}</p>
                  </div>
                )}
              </CardContent>
            </Card>
          );
        })}
      </div>

      {/* Security & Alerts */}
      <div className="grid gap-4 md:grid-cols-2">
        <Card className="animate-fade-in" style={{ animationDelay: "0.5s" }}>
          <CardHeader>
            <CardTitle className="flex items-center space-x-2">
              <Shield className="h-5 w-5 text-info" />
              <span>Security Overview</span>
            </CardTitle>
            <CardDescription>Real-time threat monitoring</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <span className="text-sm">Risk Level</span>
                <Badge variant="outline" className="text-warning">Medium</Badge>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-sm">Active Threats</span>
                <Badge variant="destructive">3</Badge>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-sm">Compliance Score</span>
                <Badge variant="outline" className="text-success">96%</Badge>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card className="animate-fade-in" style={{ animationDelay: "0.6s" }}>
          <CardHeader>
            <CardTitle className="flex items-center space-x-2">
              <Cpu className="h-5 w-5 text-primary" />
              <span>System Resources</span>
            </CardTitle>
            <CardDescription>Real-time usage monitoring</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-3">
              <div>
                <div className="flex justify-between text-sm mb-1">
                  <span>CPU Usage</span>
                  <span>{animatedValues.cpuUsage}%</span>
                </div>
                <Progress value={animatedValues.cpuUsage} className="h-2" />
              </div>
              <div>
                <div className="flex justify-between text-sm mb-1">
                  <span>Memory</span>
                  <span>{animatedValues.memoryUsage}%</span>
                </div>
                <Progress value={animatedValues.memoryUsage} className="h-2" />
              </div>
              <div>
                <div className="flex justify-between text-sm mb-1">
                  <span>Storage</span>
                  <span>45%</span>
                </div>
                <Progress value={45} className="h-2" />
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Recent Activity */}
      <Card className="animate-fade-in" style={{ animationDelay: "0.7s" }}>
        <CardHeader>
          <CardTitle>Live Activity Feed</CardTitle>
          <CardDescription>Real-time events and notifications</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="space-y-3">
            {securityAlerts.map((alert, index) => (
              <div 
                key={index} 
                className="flex items-center space-x-3 p-2 rounded-lg hover:bg-muted/50 transition-colors animate-slide-in"
                style={{ animationDelay: `${0.8 + index * 0.1}s` }}
              >
                {alert.type === 'success' && <CheckCircle className="h-4 w-4 text-success" />}
                {alert.type === 'warning' && <AlertCircle className="h-4 w-4 text-warning" />}
                {alert.type === 'info' && <Activity className="h-4 w-4 text-info" />}
                <div className="flex-1">
                  <p className="text-sm">{alert.message}</p>
                  <p className="text-xs text-muted-foreground">{alert.time}</p>
                </div>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>

      {/* Chart Placeholder */}
      <Card className="animate-fade-in" style={{ animationDelay: "0.9s" }}>
        <CardHeader>
          <CardTitle>Performance Analytics</CardTitle>
          <CardDescription>Interactive charts with hover details</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="h-48 flex items-center justify-center border-2 border-dashed border-muted-foreground/25 rounded-lg">
            <div className="text-center text-muted-foreground">
              <TrendingUp className="h-12 w-12 mx-auto mb-2" />
              <p className="font-medium">Interactive Charts</p>
              <p className="text-sm">Real-time data visualization with hover tooltips</p>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
};

export default DashboardPreview;