import { PlaybookDetail } from "../../../components/playbook-detail";

export async function generateStaticParams() {
  return [
    { techniqueId: "T1003" },
    { techniqueId: "T1046" },
    { techniqueId: "T1021" },
    { techniqueId: "T1071" },
    { techniqueId: "T1082" },
    { techniqueId: "T1059" },
    { techniqueId: "T1110" },
    { techniqueId: "T1210" },
  ];
}

export default async function PlaybookDetailPage({ params }: { params: Promise<{ techniqueId: string }> }) {
  const { techniqueId } = await params;
  return <PlaybookDetail techniqueId={techniqueId} />;
}
