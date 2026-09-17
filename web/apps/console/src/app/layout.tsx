import type { Metadata } from "next";
import "@/styles/globals.css";

export const metadata: Metadata = {
  title: "SENTINEL — Network Threat Intelligence",
  description: "Network attack forecasting platform",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" className="dark">
      <body className="min-h-screen bg-canvas-main text-ink antialiased">
        {children}
      </body>
    </html>
  );
}
