import type { Metadata } from "next";
import "./globals.css";
import { Nav } from "../components/nav";
import { TopBar } from "../components/top-bar";
import { RuleExplorerFab } from "../components/rule-explorer-fab";

export const metadata: Metadata = {
  title: "SocEyes",
  description: "Realtime detection, mapping, Suricata telemetry, orchestration, and response control",
};

export default function RootLayout({
  children,
}: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en">
      <body>
        <div className="app-shell">
          <TopBar />
          <div className="app-body">
            <Nav />
            <div className="app-main">
              <main className="content-shell">{children}</main>
              <RuleExplorerFab />
              <footer className="footer-bar">
                SocEyes — realtime detection and response across Elastic,
                Wazuh, Suricata, and packet capture.
              </footer>
            </div>
          </div>
        </div>
      </body>
    </html>
  );
}
