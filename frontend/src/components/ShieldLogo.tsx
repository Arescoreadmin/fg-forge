"use client";

import { clsx } from "clsx";

interface ShieldLogoProps {
  size?: "sm" | "md" | "lg" | "xl";
  showText?: boolean;
  className?: string;
}

const sizeClasses = {
  sm: "w-8 h-10",
  md: "w-12 h-14",
  lg: "w-16 h-20",
  xl: "w-24 h-28",
};

const textSizeClasses = {
  sm: "text-sm",
  md: "text-lg",
  lg: "text-2xl",
  xl: "text-3xl",
};

export function ShieldLogo({ size = "md", showText = true, className }: ShieldLogoProps) {
  return (
    <div className={clsx("flex items-center gap-3", className)}>
      {/* SVG Shield matching the brand logo */}
      <svg
        viewBox="0 0 100 120"
        className={clsx(sizeClasses[size], "flex-shrink-0")}
        fill="none"
        xmlns="http://www.w3.org/2000/svg"
      >
        {/* Shield outline */}
        <defs>
          {/* Gradient for the split effect */}
          <linearGradient id="shieldGradient" x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%" stopColor="#1e3a5f" />
            <stop offset="48%" stopColor="#1e3a5f" />
            <stop offset="52%" stopColor="#c45c26" />
            <stop offset="100%" stopColor="#c45c26" />
          </linearGradient>
          {/* Inner shadow effect */}
          <filter id="innerShadow" x="-20%" y="-20%" width="140%" height="140%">
            <feGaussianBlur in="SourceAlpha" stdDeviation="2" result="blur" />
            <feOffset in="blur" dx="1" dy="2" result="offsetBlur" />
            <feComposite in="SourceGraphic" in2="offsetBlur" operator="over" />
          </filter>
          {/* Metallic sheen */}
          <linearGradient id="metalSheen" x1="0%" y1="0%" x2="0%" y2="100%">
            <stop offset="0%" stopColor="rgba(255,255,255,0.15)" />
            <stop offset="50%" stopColor="rgba(255,255,255,0)" />
            <stop offset="100%" stopColor="rgba(0,0,0,0.2)" />
          </linearGradient>
        </defs>

        {/* Main shield body */}
        <path
          d="M50 5 L90 20 L90 55 C90 85 50 115 50 115 C50 115 10 85 10 55 L10 20 Z"
          fill="url(#shieldGradient)"
          stroke="#2a2a2a"
          strokeWidth="3"
          filter="url(#innerShadow)"
        />

        {/* Metallic overlay */}
        <path
          d="M50 5 L90 20 L90 55 C90 85 50 115 50 115 C50 115 10 85 10 55 L10 20 Z"
          fill="url(#metalSheen)"
        />

        {/* Center divider line */}
        <path
          d="M50 15 L50 105"
          stroke="#1a1a1a"
          strokeWidth="2"
          opacity="0.6"
        />

        {/* Center emblem - diamond shape with dots */}
        <g transform="translate(50, 55)">
          {/* Diamond outline */}
          <path
            d="M0 -20 L12 0 L0 20 L-12 0 Z"
            fill="#1a1a1a"
            stroke="#3d3d3d"
            strokeWidth="1.5"
          />
          {/* Inner diamond */}
          <path
            d="M0 -14 L8 0 L0 14 L-8 0 Z"
            fill="#0a0a0a"
          />
          {/* Three dots */}
          <circle cx="0" cy="-4" r="2" fill="#5c5c5c" />
          <circle cx="-4" cy="4" r="2" fill="#5c5c5c" />
          <circle cx="4" cy="4" r="2" fill="#5c5c5c" />
        </g>

        {/* Border highlight */}
        <path
          d="M50 8 L87 22 L87 55 C87 83 50 111 50 111"
          fill="none"
          stroke="rgba(255,255,255,0.1)"
          strokeWidth="1"
        />
      </svg>

      {showText && (
        <span
          className={clsx(
            "font-display font-bold tracking-[0.2em] uppercase text-frost-dark-200",
            textSizeClasses[size]
          )}
        >
          FROSTGATE
        </span>
      )}
    </div>
  );
}
