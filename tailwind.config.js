/** @type {import('tailwindcss').Config} */
module.exports = {
  darkMode: "class",
  content: ["./popup/**/*.{html,js}"],
  theme: {
      extend: {
          colors: {
              "on-secondary-container": "#aeb9d0",
              "secondary-fixed": "#d8e3fb",
              "inverse-surface": "#dee3e8",
              "surface-container": "#1b2024",
              "tertiary-fixed": "#ffddb8",
              "on-primary-fixed": "#001e2c",
              "outline": "#87929a",
              "primary-fixed": "#c4e7ff",
              "primary": "#8ed5ff",
              "on-secondary-fixed": "#111c2d",
              "surface-variant": "#303539",
              "surface-container-low": "#171c20",
              "error": "#ffb4ab",
              "on-tertiary-fixed-variant": "#653e00",
              "surface": "#0f1418",
              "secondary-fixed-dim": "#bcc7de",
              "surface-container-high": "#252b2e",
              "primary-container": "#38bdf8",
              "tertiary-container": "#f1a02b",
              "surface-tint": "#7bd0ff",
              "primary-fixed-dim": "#7bd0ff",
              "surface-bright": "#343a3e",
              "on-primary-container": "#004965",
              "on-error": "#690005",
              "on-background": "#dee3e8",
              "on-surface-variant": "#bdc8d1",
              "background": "#0f1418",
              "on-secondary": "#263143",
              "secondary-container": "#3e495d",
              "tertiary": "#ffc176",
              "surface-dim": "#0f1418",
              "on-error-container": "#ffdad6",
              "on-tertiary-fixed": "#2a1700",
              "on-surface": "#dee3e8",
              "on-primary-fixed-variant": "#004c69",
              "on-tertiary": "#472a00",
              "error-container": "#93000a",
              "inverse-primary": "#00668a",
              "outline-variant": "#3e484f",
              "inverse-on-surface": "#2c3135",
              "on-tertiary-container": "#613b00",
              "surface-container-highest": "#303539",
              "on-primary": "#00354a",
              "on-secondary-fixed-variant": "#3c475a",
              "secondary": "#bcc7de",
              "tertiary-fixed-dim": "#ffb960",
              "surface-container-lowest": "#0a0f12"
          },
          borderRadius: {
              "DEFAULT": "0.25rem",
              "lg": "0.5rem",
              "xl": "0.75rem",
              "full": "9999px"
          },
          spacing: {
              "stack-gap": "0.75rem",
              "container-padding": "1rem",
              "section-margin": "1.25rem",
              "inline-gap": "0.5rem"
          },
          fontFamily: {
              "headline-sm": ["Geist", "sans-serif"],
              "display-score": ["Geist", "sans-serif"],
              "code-xs": ["JetBrains Mono", "monospace"],
              "body-md": ["Inter", "sans-serif"],
              "label-caps": ["JetBrains Mono", "monospace"]
          },
          fontSize: {
              "headline-sm": ["18px", { lineHeight: "24px", fontWeight: "600" }],
              "display-score": ["48px", { lineHeight: "48px", letterSpacing: "-0.04em", fontWeight: "700" }],
              "code-xs": ["11px", { lineHeight: "16px", letterSpacing: "0.05em", fontWeight: "500" }],
              "body-md": ["14px", { lineHeight: "20px", fontWeight: "400" }],
              "label-caps": ["10px", { lineHeight: "12px", fontWeight: "700" }]
          }
      }
  }
}
