import type { Config } from "tailwindcss";

const config: Config = {
  content: ["./src/**/*.{js,ts,jsx,tsx,mdx}"],
  theme: {
    extend: {
      colors: {
        theme: {
          primary: "#3353FE",
          "primary-hover": "#1F4CEE",
          "primary-light": "rgba(51, 83, 254, 0.08)",
          accent: "#32B7EE",
          "accent-hover": "#41A7FE",
          border: "hsl(0 0% 89.8%)",
        },
        palette: {
          "blue-deep": "#1F4CEE",
          "blue-vibrant": "#3353FE",
          "blue-medium": "#506EEE",
          "blue-light": "#41A7FE",
          cyan: "#32B7EE",
          "soft-blue": "#7C8EE3",
          periwinkle: "#AAB9ED",
          "light-blue": "#C3CDEC",
          "gray-blue": "#DCDDE6",
          "light-gray": "#E6E5EC",
        },
        brand: {
          50: "#eff6ff",
          100: "#dbeafe",
          200: "#bfdbfe",
          300: "#93c5fd",
          400: "#60a5fa",
          500: "#3b82f6",
          600: "#2563eb",
          700: "#1d4ed8",
          800: "#1e40af",
          900: "#1e3a8a",
          950: "#172554",
        },
        surface: {
          0: "#ffffff",
          50: "#f8fafc",
          100: "#f1f5f9",
          200: "#e2e8f0",
          300: "#cbd5e1",
          400: "#94a3b8",
          500: "#64748b",
          600: "#475569",
          700: "#334155",
          800: "#1e293b",
          900: "#0f172a",
          950: "#020617",
        },
      },
      fontFamily: {
        sans: ["var(--font-inter)", "system-ui", "-apple-system", "sans-serif"],
        heading: [
          "var(--font-maven-pro)",
          "system-ui",
          "-apple-system",
          "sans-serif",
        ],
        mono: ["JetBrains Mono", "Fira Code", "monospace"],
      },
      borderRadius: {
        lg: "0.5rem",
        md: "6px",
        sm: "4px",
        none: "0",
        full: "9999px",
      },
      backgroundImage: {
        "theme-gradient":
          "linear-gradient(to bottom, #1F4CEE 0%, #41A7FE 50%, #32B7EE 100%)",
        "theme-gradient-horizontal":
          "linear-gradient(to right, #1F4CEE 0%, #41A7FE 50%, #32B7EE 100%)",
        "theme-gradient-button":
          "linear-gradient(to right, #1F4CEE 0%, #41A7FE 50%, #32B7EE 100%)",
        "theme-gradient-button-hover":
          "linear-gradient(to right, #1F4CEE 0%, #3353FE 50%, #41A7FE 100%)",
      },
      animation: {
        "fade-in": "fadeIn 0.3s ease-in-out",
        "slide-up": "slideUp 0.3s ease-out",
        "pulse-slow": "pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite",
      },
      keyframes: {
        fadeIn: {
          "0%": { opacity: "0" },
          "100%": { opacity: "1" },
        },
        slideUp: {
          "0%": { opacity: "0", transform: "translateY(10px)" },
          "100%": { opacity: "1", transform: "translateY(0)" },
        },
      },
    },
  },
  plugins: [],
};

export default config;
