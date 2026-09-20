import type { Metadata } from "next";
import { Inter, IBM_Plex_Mono } from "next/font/google";

import "./globals.css";
import { Nav } from "../components/nav";
import { RuleExplorerFab } from "../components/rule-explorer-fab";

const bodyFont = Inter({
  subsets: ["latin"],
  weight: ["400", "500", "600", "700"],
  variable: "--font-body",
  display: "swap",
});

const monoFont = IBM_Plex_Mono({
  subsets: ["latin"],
  weight: ["400", "500", "600", "700"],
  variable: "--font-mono",
  display: "swap",
});

export const metadata: Metadata = {
  title: "FDA Cyber Control",
  description: "Realtime detection, mapping, Suricata telemetry, orchestration, and response control",
};

export default function RootLayout({
  children,
}: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en">
      <body
        className={`${bodyFont.variable} ${monoFont.variable}`}
      >
        <div className="app-shell">
          <Nav />
          <div className="app-main">
            <main className="content-shell">{children}</main>
            <RuleExplorerFab />
            <footer className="footer-bar">
              FDA Cyber Control — realtime detection and response across Elastic,
              Wazuh, Suricata, and packet capture.
            </footer>
          </div>
        </div>
      </body>
    </html>
  );
}
