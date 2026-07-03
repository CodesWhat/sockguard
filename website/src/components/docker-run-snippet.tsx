import { Terminal } from "lucide-react";
import { Card, CardContent } from "@/components/ui/card";
import { SITE_CONFIG } from "@/lib/site-config";

type Props = {
  cardClassName?: string;
  contentClassName?: string;
  iconClassName?: string;
  headerClassName?: string;
  label?: string;
};

export function DockerRunSnippet({
  cardClassName = "border-neutral-200 bg-neutral-950 text-left dark:border-neutral-800",
  contentClassName = "pt-6",
  iconClassName = "h-4 w-4",
  headerClassName = "mb-3 flex items-center gap-2 text-neutral-500",
  label = "Terminal",
}: Props) {
  return (
    <Card className={cardClassName}>
      <CardContent className={contentClassName}>
        <div className={headerClassName}>
          <Terminal className={iconClassName} />
          <span className="text-xs font-medium uppercase tracking-wider">{label}</span>
        </div>
        <pre className="overflow-x-auto text-sm">
          <code className="text-neutral-300">
            <span className="text-neutral-500">$</span>{" "}
            <span className="text-amber-300">docker run</span> -d \{"\n"}
            {"  "}--name <span className="text-rose-300">sockguard</span> \{"\n"}
            {"  "}-v{" "}
            <span className="text-rose-300">/var/run/docker.sock:/var/run/docker.sock:ro</span> \
            {"\n"}
            {"  "}-v <span className="text-rose-300">/var/run/sockguard:/var/run/sockguard</span> \
            {"\n"}
            {"  "}-e SOCKGUARD_LISTEN_SOCKET=
            <span className="text-rose-300">/var/run/sockguard/sockguard.sock</span> \{"\n"}
            {"  "}
            <span className="text-rose-300">{SITE_CONFIG.dockerImage}</span>
          </code>
        </pre>
      </CardContent>
    </Card>
  );
}
