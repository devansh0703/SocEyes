import { RuleDetail } from "../../../components/rule-detail";

export async function generateStaticParams() {
  return [
    { ruleId: "ET SCAN Potential SSH Scan" },
    { ruleId: "ET SCAN Potential HTTP Traffic on Uncommon Port" },
    { ruleId: "ET Policy SSH Inbound Connection on Common SSH Port" },
    { ruleId: "wazuh-scan-001" },
    { ruleId: "wazuh-suspicious-002" },
    { ruleId: "wazuh-brute-force-003" },
    { ruleId: "wazuh-cred-dump-004" },
    { ruleId: "suricata-alert-001" },
  ];
}

export default async function RuleDetailPage({ params }: { params: Promise<{ ruleId: string }> }) {
  const { ruleId } = await params;
  return <RuleDetail ruleId={ruleId} />;
}
