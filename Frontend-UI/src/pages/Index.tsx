import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import LineBackground from "@/components/LineBackground";
import Header from "@/components/Header";
import DashboardPreview from "@/components/DashboardPreview";
import { PerformanceChart, CostBreakdownChart } from "@/components/Charts";
import { Link } from "react-router-dom";
import { ArrowRight, Zap, Shield, BarChart3, DollarSign, Star, Check, Activity } from "lucide-react";

const Index = () => {
  const pricingTiers = [
    {
      name: "Starter",
      price: "$29",
      period: "/month",
      description: "Perfect for small teams getting started",
      features: ["5 agents", "Basic monitoring", "Email support", "Basic analytics"],
      popular: false
    },
    {
      name: "Professional", 
      price: "$99",
      period: "/month",
      description: "Advanced features for growing businesses",
      features: ["25 agents", "Advanced analytics", "Priority support", "Custom integrations", "API access"],
      popular: true
    },
    {
      name: "Enterprise",
      price: "$299", 
      period: "/month",
      description: "Full-featured solution for large organizations",
      features: ["Unlimited agents", "Custom features", "24/7 support", "White-label options", "On-premise deployment"],
      popular: false
    },
    {
      name: "Custom",
      price: "Contact",
      period: "us",
      description: "Tailored solutions for enterprise needs",
      features: ["Custom pricing", "Dedicated support", "Custom development", "SLA guarantees", "Training included"],
      popular: false
    }
  ];

  return (
    <div className="min-h-screen bg-background relative overflow-hidden">
      <LineBackground />
      <Header />
      
      <div className="relative z-10">
        {/* Hero Section */}
        <section className="min-h-screen flex flex-col items-center justify-center px-6 text-center">
          <div className="max-w-4xl mx-auto space-y-8">
            <div className="space-y-4 animate-fade-in">
              <Badge variant="outline" className="px-4 py-2">
                <Zap className="w-4 h-4 mr-2" />
                Advanced AI Analytics Platform
              </Badge>
              <h1 className="text-5xl lg:text-7xl font-bold tracking-tight">
                AI HR Agent
                <span className="block text-muted-foreground">for your AI Agents</span>
              </h1>
              <p className="text-xl text-muted-foreground max-w-2xl mx-auto">
                Monitor performance, track costs, ensure security, and optimize your AI agents with real-time analytics and comprehensive insights.
              </p>
            </div>

            <div className="flex flex-col sm:flex-row gap-4 justify-center animate-fade-in" style={{ animationDelay: "0.2s" }}>
              <Button size="lg" asChild className="px-8">
                <Link to="/setup">
                  Get Started
                  <ArrowRight className="ml-2 h-5 w-5" />
                </Link>
              </Button>
              <Button variant="outline" size="lg" asChild className="px-8">
                <Link to="/dashboard">
                  View Dashboard
                  <BarChart3 className="ml-2 h-5 w-5" />
                </Link>
              </Button>
            </div>

            {/* Key Features */}
            <div className="grid grid-cols-1 md:grid-cols-4 gap-6 mt-16 animate-fade-in" style={{ animationDelay: "0.4s" }}>
              {[
                { icon: BarChart3, title: "Performance Metrics", desc: "Track success rates and response times" },
                { icon: Shield, title: "Security Monitoring", desc: "Real-time threat detection and compliance" },
                { icon: DollarSign, title: "Cost Analytics", desc: "Monitor token usage and spending" },
                { icon: Zap, title: "Real-time Insights", desc: "Live data and instant notifications" }
              ].map((feature, index) => (
                <Card key={index} className="border-muted/50 hover:border-primary/50 transition-colors">
                  <CardContent className="pt-6 text-center">
                    <feature.icon className="h-12 w-12 mx-auto mb-4 text-primary" />
                    <h3 className="font-semibold mb-2">{feature.title}</h3>
                    <p className="text-sm text-muted-foreground">{feature.desc}</p>
                  </CardContent>
                </Card>
              ))}
            </div>
          </div>
        </section>

        {/* Interactive Dashboard Preview */}
        <section className="py-20 px-6">
          <div className="max-w-6xl mx-auto">
            <div className="text-center mb-16 animate-fade-in">
              <h2 className="text-4xl font-bold mb-4">Interactive Dashboard Preview</h2>
              <p className="text-xl text-muted-foreground">
                Experience real-time analytics with hover interactions and animated insights
              </p>
            </div>
            
            <DashboardPreview />
            
            {/* Chart Preview Section */}
            <div className="mt-16 grid grid-cols-1 lg:grid-cols-2 gap-8">
              <Card className="p-6 bg-card/50 backdrop-blur border-border/50">
                <div className="flex items-center gap-2 mb-4">
                  <Activity className="h-5 w-5 text-primary" />
                  <h3 className="text-lg font-semibold">Performance Analytics</h3>
                </div>
                <PerformanceChart />
              </Card>
              
              <Card className="p-6 bg-card/50 backdrop-blur border-border/50">
                <div className="flex items-center gap-2 mb-4">
                  <DollarSign className="h-5 w-5 text-primary" />
                  <h3 className="text-lg font-semibold">Cost Breakdown by LLM</h3>
                </div>
                <CostBreakdownChart />
              </Card>
            </div>
          </div>
        </section>

        {/* Pricing Section */}
        <section className="py-20 px-6 bg-muted/30">
          <div className="max-w-6xl mx-auto">
            <div className="text-center mb-16 animate-fade-in">
              <h2 className="text-4xl font-bold mb-4">Choose Your Plan</h2>
              <p className="text-xl text-muted-foreground">
                Transparent pricing with no hidden fees. Scale as you grow.
              </p>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
              {pricingTiers.map((tier, index) => (
                <Card 
                  key={tier.name} 
                  className={`relative animate-fade-in hover:scale-105 transition-transform ${
                    tier.popular ? 'border-primary shadow-lg' : ''
                  }`}
                  style={{ animationDelay: `${index * 0.1}s` }}
                >
                  {tier.popular && (
                    <div className="absolute -top-3 left-1/2 transform -translate-x-1/2">
                      <Badge className="px-3 py-1">
                        <Star className="w-3 h-3 mr-1" />
                        Most Popular
                      </Badge>
                    </div>
                  )}
                  
                  <CardHeader className="text-center">
                    <CardTitle className="text-2xl">{tier.name}</CardTitle>
                    <div className="mt-4">
                      <span className="text-4xl font-bold">{tier.price}</span>
                      <span className="text-muted-foreground">{tier.period}</span>
                    </div>
                    <CardDescription className="mt-2">{tier.description}</CardDescription>
                  </CardHeader>
                  
                  <CardContent>
                    <ul className="space-y-3">
                      {tier.features.map((feature, featureIndex) => (
                        <li key={featureIndex} className="flex items-center text-sm">
                          <Check className="w-4 h-4 mr-3 text-success" />
                          {feature}
                        </li>
                      ))}
                    </ul>
                    
                    <Button 
                      className="w-full mt-6" 
                      variant={tier.popular ? "default" : "outline"}
                      asChild
                    >
                      <Link to="/setup">
                        {tier.name === "Custom" ? "Contact Sales" : "Get Started"}
                      </Link>
                    </Button>
                  </CardContent>
                </Card>
              ))}
            </div>
          </div>
        </section>

        {/* Revenue Streams */}
        <section className="py-20 px-6">
          <div className="max-w-4xl mx-auto text-center">
            <h2 className="text-3xl font-bold mb-8 animate-fade-in">Revenue Streams</h2>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
              <Card className="animate-fade-in" style={{ animationDelay: "0.1s" }}>
                <CardHeader>
                  <CardTitle className="flex items-center">
                    <DollarSign className="w-5 h-5 mr-2 text-success" />
                    Subscription Model
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <p className="text-muted-foreground">
                    Recurring monthly and annual subscriptions provide predictable revenue 
                    with automatic scaling based on usage and features.
                  </p>
                </CardContent>
              </Card>
              
              <Card className="animate-fade-in" style={{ animationDelay: "0.2s" }}>
                <CardHeader>
                  <CardTitle className="flex items-center">
                    <Star className="w-5 h-5 mr-2 text-warning" />
                    Enterprise Solutions
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <p className="text-muted-foreground">
                    Custom enterprise pricing for white-label solutions, on-premise 
                    deployments, and dedicated support contracts.
                  </p>
                </CardContent>
              </Card>
            </div>
          </div>
        </section>

        {/* Footer */}
        <footer className="py-12 px-6 border-t bg-card">
          <div className="max-w-4xl mx-auto text-center">
            <p className="text-muted-foreground">
              © 2024 Analytics Dashboard. Built for the future of AI monitoring.
            </p>
          </div>
        </footer>
      </div>
    </div>
  );
};

export default Index;
