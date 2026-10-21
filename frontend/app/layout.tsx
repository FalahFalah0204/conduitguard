import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "ConduitGuard — Network change validation",
  description: "Validate firewall policy changes before deployment with offline simulation and explainable security findings.",
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return <html lang="id"><body>{children}</body></html>;
}
