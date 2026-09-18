import React from "react";
import "./globals.css";
// Belt-and-suspenders: also import the React Flow base stylesheet at the
// app root (it is already imported directly by AgenticScanTab.tsx, which
// is sufficient in Next.js 13+ app-router client components, but importing
// it here too guarantees it is bundled and ordered ahead of any component-
// level CSS regardless of where/when that component mounts).
import "@xyflow/react/dist/style.css";

export const metadata = {
  title: "AI Code Guardian",
  description: "Multi-language, UST-driven, evidence-grounded code analysis platform",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className="dark">
      <body className="text-slate-100 font-sans antialiased min-h-screen">
        {children}
      </body>
    </html>
  );
}
