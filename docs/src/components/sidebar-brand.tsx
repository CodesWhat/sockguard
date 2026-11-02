import Image from "next/image";
import { BASE_PATH, SITE_CONFIG } from "@/lib/site-config";

// Sidebar banner slot: mascot and product name above the page tree.
export function SidebarBrand() {
  return (
    <div className="sb-h">
      <Image src={`${BASE_PATH}/img/dog-64.webp`} alt="" width={36} height={36} unoptimized />
      <b>{SITE_CONFIG.name} docs</b>
    </div>
  );
}
