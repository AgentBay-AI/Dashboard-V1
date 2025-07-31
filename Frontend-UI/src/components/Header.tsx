import { Button } from "@/components/ui/button";
import { useTheme } from "@/components/ThemeProvider";
import { Github, MessageSquare, Moon, Sun, BarChart3 } from "lucide-react";
import { Link } from "react-router-dom";

const Header = () => {
  const { theme, setTheme } = useTheme();

  return (
    <header className="fixed top-0 right-0 z-50 p-4">
      <div className="flex items-center space-x-2">
        <Button
          variant="ghost"
          size="sm"
          asChild
          className="text-foreground hover:bg-accent"
        >
          <a
            href="https://discord.gg/analytics"
            target="_blank"
            rel="noopener noreferrer"
            aria-label="Discord"
          >
            <MessageSquare className="h-4 w-4" />
          </a>
        </Button>
        
        <Button
          variant="ghost"
          size="sm"
          asChild
          className="text-foreground hover:bg-accent"
        >
          <a
            href="https://twitter.com/analytics"
            target="_blank"
            rel="noopener noreferrer"
            aria-label="Twitter/X"
          >
            <svg
              className="h-4 w-4"
              fill="currentColor"
              viewBox="0 0 24 24"
              aria-hidden="true"
            >
              <path d="M18.244 2.25h3.308l-7.227 8.26 8.502 11.24H16.17l-5.214-6.817L4.99 21.75H1.68l7.73-8.835L1.254 2.25H8.08l4.713 6.231zm-1.161 17.52h1.833L7.084 4.126H5.117z" />
            </svg>
          </a>
        </Button>

        <Button
          variant="ghost"
          size="sm"
          asChild
          className="text-foreground hover:bg-accent"
        >
          <a
            href="https://github.com/analytics-dashboard"
            target="_blank"
            rel="noopener noreferrer"
            aria-label="GitHub"
          >
            <Github className="h-4 w-4" />
          </a>
        </Button>

        <Button
          variant="ghost"
          size="sm"
          asChild
          className="text-foreground hover:bg-accent"
        >
          <Link to="/dashboard" aria-label="Dashboard">
            <BarChart3 className="h-4 w-4" />
          </Link>
        </Button>

        <Button
          variant="ghost"
          size="sm"
          onClick={() => setTheme(theme === "light" ? "dark" : "light")}
          className="text-foreground hover:bg-accent"
          aria-label="Toggle theme"
        >
          {theme === "light" ? (
            <Moon className="h-4 w-4" />
          ) : (
            <Sun className="h-4 w-4" />
          )}
        </Button>
      </div>
    </header>
  );
};

export default Header;