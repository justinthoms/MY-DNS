import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "ISP NetControl",
  description: "DNS filtering and firewall management for ISPs",
  robots: { index: false, follow: false },
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
