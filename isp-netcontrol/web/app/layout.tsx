import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "ISP NetControl",
  description: "DNS filtering and firewall management for ISPs",
  robots: { index: false, follow: false },
};

// Applies the saved theme before the first paint (default: dark).
const themeScript = `try{var t=localStorage.getItem("nc-theme")||"dark";if(t!=="system")document.documentElement.dataset.theme=t}catch(e){document.documentElement.dataset.theme="dark"}`;

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" suppressHydrationWarning>
      <head>
        <script dangerouslySetInnerHTML={{ __html: themeScript }} />
      </head>
      <body>{children}</body>
    </html>
  );
}
