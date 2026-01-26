"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { clsx } from "clsx";
import { ShieldLogo } from "./ShieldLogo";
import {
  LayoutDashboard,
  Zap,
  Trophy,
  Activity,
  Settings,
  Menu,
  X,
} from "lucide-react";
import { useState } from "react";

const navItems = [
  { href: "/", label: "Dashboard", icon: LayoutDashboard },
  { href: "/spawn", label: "Spawn", icon: Zap },
  { href: "/leaderboard", label: "Leaderboard", icon: Trophy },
  { href: "/activity", label: "Activity", icon: Activity },
];

export function Navbar() {
  const pathname = usePathname();
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

  return (
    <header className="sticky top-0 z-50 border-b border-frost-dark-800 bg-frost-dark-900/95 backdrop-blur-sm">
      <nav className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-16">
          {/* Logo */}
          <Link href="/" className="flex-shrink-0 hover:opacity-90 transition-opacity">
            <ShieldLogo size="sm" showText={true} />
          </Link>

          {/* Desktop Navigation */}
          <div className="hidden md:flex items-center space-x-1">
            {navItems.map((item) => {
              const Icon = item.icon;
              const isActive = pathname === item.href;

              return (
                <Link
                  key={item.href}
                  href={item.href}
                  className={clsx(
                    "flex items-center gap-2 px-4 py-2 rounded-lg font-display font-medium text-sm uppercase tracking-wider transition-all duration-200",
                    isActive
                      ? "bg-frost-dark-800 text-frost-orange-400"
                      : "text-frost-dark-400 hover:text-frost-dark-200 hover:bg-frost-dark-800/50"
                  )}
                >
                  <Icon size={16} />
                  {item.label}
                </Link>
              );
            })}
          </div>

          {/* Right side actions */}
          <div className="hidden md:flex items-center gap-4">
            <button className="p-2 text-frost-dark-400 hover:text-frost-dark-200 transition-colors">
              <Settings size={20} />
            </button>
            <button className="btn-primary text-sm py-2">
              Connect
            </button>
          </div>

          {/* Mobile menu button */}
          <button
            onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
            className="md:hidden p-2 text-frost-dark-400 hover:text-frost-dark-200"
          >
            {mobileMenuOpen ? <X size={24} /> : <Menu size={24} />}
          </button>
        </div>

        {/* Mobile Navigation */}
        {mobileMenuOpen && (
          <div className="md:hidden py-4 border-t border-frost-dark-800">
            <div className="flex flex-col space-y-2">
              {navItems.map((item) => {
                const Icon = item.icon;
                const isActive = pathname === item.href;

                return (
                  <Link
                    key={item.href}
                    href={item.href}
                    onClick={() => setMobileMenuOpen(false)}
                    className={clsx(
                      "flex items-center gap-3 px-4 py-3 rounded-lg font-display font-medium uppercase tracking-wider transition-all duration-200",
                      isActive
                        ? "bg-frost-dark-800 text-frost-orange-400"
                        : "text-frost-dark-400 hover:text-frost-dark-200 hover:bg-frost-dark-800/50"
                    )}
                  >
                    <Icon size={18} />
                    {item.label}
                  </Link>
                );
              })}
              <div className="pt-4 border-t border-frost-dark-800">
                <button className="btn-primary w-full text-sm py-2">
                  Connect
                </button>
              </div>
            </div>
          </div>
        )}
      </nav>
    </header>
  );
}
