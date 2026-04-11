import type { Metadata } from "next";
import type { ReactNode } from "react";
import { Providers } from "./providers";
import "@/styles/globals.css";

export const metadata: Metadata = {
  title: "Web Insight — Domain Intelligence Platform",
  description:
    "Scan websites for tech stack, DNS records, and SSL certificates. Monitor your brand domains with automated scanning.",
  keywords: [
    "Web Insight",
    "tech stack analyzer",
    "SSL certificate",
    "domain monitoring",
    "website scanner",
  ],
};

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="en" suppressHydrationWarning>
      <body suppressHydrationWarning>
        <Providers>{children}</Providers>
      </body>
    </html>
  );
}
