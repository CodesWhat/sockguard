import Link from "next/link";
import { CliDemo } from "@/components/cli-demo";
import { ThemeToggle } from "@/components/theme-toggle";

export default function CliPreviewPage() {
  return (
    <div className="min-h-screen bg-neutral-50 text-neutral-900 dark:bg-neutral-950 dark:text-neutral-50">
      <header className="mx-auto flex max-w-5xl items-center justify-between px-6 pt-8">
        <Link
          href="/"
          className="text-sm text-neutral-500 hover:text-fuchsia-600 dark:hover:text-fuchsia-400"
        >
          ← sockguard
        </Link>
        <ThemeToggle />
      </header>

      <main className="mx-auto max-w-5xl px-6 pb-24 pt-12">
        <div className="mb-10">
          <h1 className="text-3xl font-semibold tracking-tight">CLI tour</h1>
          <p className="mt-2 max-w-2xl text-sm text-neutral-600 dark:text-neutral-400">
            A mocked terminal that cycles through the real sockguard subcommands. Loops forever,
            respects system theme, and works with no JavaScript runtime outside React.
          </p>
        </div>

        <CliDemo />
      </main>
    </div>
  );
}
