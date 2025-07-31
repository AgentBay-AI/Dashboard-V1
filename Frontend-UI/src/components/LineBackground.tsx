import { useEffect, useRef } from "react";
import { useTheme } from "./ThemeProvider";

const LineBackground = () => {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const { theme } = useTheme();

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    const resizeCanvas = () => {
      canvas.width = window.innerWidth;
      canvas.height = window.innerHeight;
      drawLines();
    };

    const drawLines = () => {
      ctx.clearRect(0, 0, canvas.width, canvas.height);
      
      // Enhanced visibility for both themes with darker lines
      if (theme === 'dark') {
        ctx.strokeStyle = 'hsl(210 40% 85%)'; // Lighter gray for dark theme
        ctx.globalAlpha = 0.7;
      } else {
        ctx.strokeStyle = 'hsl(220 13% 15%)'; // Darker gray for light theme  
        ctx.globalAlpha = 0.6;
      }
      
      ctx.lineWidth = 1;
      ctx.setLineDash([5, 5]);

      // Central convergence point
      const centerX = canvas.width / 2;
      const centerY = canvas.height / 2;

      // Draw lines converging to center from various angles
      const numLines = 24;
      const radius = Math.max(canvas.width, canvas.height);

      for (let i = 0; i < numLines; i++) {
        const angle = (i * 360) / numLines;
        const radians = (angle * Math.PI) / 180;
        
        const startX = centerX + Math.cos(radians) * radius;
        const startY = centerY + Math.sin(radians) * radius;

        ctx.beginPath();
        ctx.moveTo(startX, startY);
        ctx.lineTo(centerX, centerY);
        ctx.stroke();
      }

      // Add some random connecting lines for visual interest
      for (let i = 0; i < 8; i++) {
        const x1 = Math.random() * canvas.width;
        const y1 = Math.random() * canvas.height;
        const x2 = Math.random() * canvas.width;
        const y2 = Math.random() * canvas.height;

        ctx.beginPath();
        ctx.moveTo(x1, y1);
        ctx.lineTo(x2, y2);
        ctx.stroke();
      }
    };

    resizeCanvas();
    window.addEventListener("resize", resizeCanvas);

    return () => {
      window.removeEventListener("resize", resizeCanvas);
    };
  }, [theme]); // Add theme dependency to redraw when theme changes

  return (
    <canvas
      ref={canvasRef}
      className="fixed inset-0 pointer-events-none z-0"
      style={{ 
        background: "transparent",
        opacity: theme === 'dark' ? 0.8 : 0.7 
      }}
    />
  );
};

export default LineBackground;