import type { Metadata } from "next";
import { Exo_2 as Ndot, Nunito_Sans as N1, IBM_Plex_Mono as IbmPixel } from "next/font/google";

import "./globals.css";
import { Nav } from "../components/nav";
import { RuleExplorerFab } from "../components/rule-explorer-fab";

const headingFont = Ndot({
  subsets: ["latin"],
  weight: ["700", "800", "900"],
  variable: "--font-heading",
  display: "swap",
});

const bodyFont = N1({
  subsets: ["latin"],
  weight: ["300", "400", "600", "700"],
  variable: "--font-body",
  display: "swap",
});

const monoFont = IbmPixel({
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
        className={`${headingFont.variable} ${bodyFont.variable} ${monoFont.variable} font-body`}
      >
        <div className="app-shell">
          <Nav />
          <div className="app-main">
            <main className="content-shell">{children}</main>
            <RuleExplorerFab />
            <footer className="footer-bar">
              Existing rules only. Live telemetry from Elastic, Wazuh, Suricata,
              and ZeroClaw-compatible orchestration hands.
            </footer>
          </div>
        </div>
      </body>
    </html>
  );
}