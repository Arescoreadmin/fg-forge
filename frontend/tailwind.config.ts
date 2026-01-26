import type { Config } from "tailwindcss";

const config: Config = {
  content: [
    "./src/pages/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/components/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/app/**/*.{js,ts,jsx,tsx,mdx}",
  ],
  theme: {
    extend: {
      colors: {
        // FrostGate brand colors extracted from logo
        frost: {
          // Steel blue side of shield
          blue: {
            50: "#e8eef5",
            100: "#c5d4e6",
            200: "#9eb7d4",
            300: "#7799c1",
            400: "#5a82b3",
            500: "#3d6ba5",
            600: "#1e3a5f", // Primary steel blue
            700: "#182e4a",
            800: "#122236",
            900: "#0c1621",
            950: "#060b11",
          },
          // Burnt orange/rust side of shield
          orange: {
            50: "#fef3ed",
            100: "#fce3d4",
            200: "#f9c4a8",
            300: "#f5a07a",
            400: "#e87a4d",
            500: "#c45c26", // Primary burnt orange
            600: "#a34a1e",
            700: "#833b18",
            800: "#6a3015",
            900: "#562712",
            950: "#2e140a",
          },
          // Deep blacks and grays
          dark: {
            50: "#f5f5f5",
            100: "#e0e0e0",
            200: "#b8b8b8",
            300: "#8a8a8a",
            400: "#5c5c5c",
            500: "#3d3d3d",
            600: "#2a2a2a",
            700: "#1f1f1f",
            800: "#141414",
            900: "#0a0a0a", // Primary deep black
            950: "#050505",
          },
        },
      },
      fontFamily: {
        // Technical sans-serif matching the logo
        display: ["var(--font-rajdhani)", "system-ui", "sans-serif"],
        body: ["var(--font-inter)", "system-ui", "sans-serif"],
        mono: ["var(--font-jetbrains)", "monospace"],
      },
      backgroundImage: {
        // Gradient matching shield split
        "shield-gradient": "linear-gradient(135deg, #1e3a5f 0%, #1e3a5f 50%, #c45c26 50%, #c45c26 100%)",
        // Subtle ember glow
        "ember-glow": "radial-gradient(ellipse at bottom right, rgba(196, 92, 38, 0.15) 0%, transparent 70%)",
        // Steel texture
        "steel-texture": "linear-gradient(180deg, rgba(30, 58, 95, 0.1) 0%, rgba(10, 10, 10, 0.95) 100%)",
      },
      boxShadow: {
        "ember": "0 0 30px rgba(196, 92, 38, 0.3)",
        "frost": "0 0 30px rgba(30, 58, 95, 0.3)",
        "shield": "0 4px 20px rgba(0, 0, 0, 0.5), inset 0 1px 0 rgba(255, 255, 255, 0.1)",
      },
      animation: {
        "pulse-ember": "pulse-ember 3s ease-in-out infinite",
        "shimmer": "shimmer 2s linear infinite",
      },
      keyframes: {
        "pulse-ember": {
          "0%, 100%": { opacity: "0.6" },
          "50%": { opacity: "1" },
        },
        shimmer: {
          "0%": { backgroundPosition: "-200% 0" },
          "100%": { backgroundPosition: "200% 0" },
        },
      },
    },
  },
  plugins: [],
};

export default config;
