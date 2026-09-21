import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "SocEyes — Open Network Detection & Response",
  description:
    "SocEyes captures raw packets, evaluates 6,500+ detection rules from Sigma, Elastic, Wazuh and Panther against live traffic, triages every alert with AI, and can enforce containment on the wire.",
};

export default function RootLayout({
  children,
}: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
