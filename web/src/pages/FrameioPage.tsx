import {
  ArrowRight,
  CheckCircle2,
  ClipboardList,
  Cloud,
  FolderSearch,
  KeyRound,
  Link2,
  LockKeyhole,
  MonitorCheck,
  Network,
  PlayCircle,
  ShieldCheck,
  UploadCloud,
} from "lucide-react";
import { Badge } from "@nous-research/ui/ui/components/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { cn } from "@/lib/utils";
import { PluginSlot } from "@/plugins";

const toolCards = [
  {
    icon: KeyRound,
    name: "frameio_login",
    description: "Launches Adobe IMS OAuth and stores Frame.io token state locally under Hermes home.",
  },
  {
    icon: MonitorCheck,
    name: "frameio_status",
    description: "Reports auth readiness, token presence, refresh state, and missing configuration without leaking secrets.",
  },
  {
    icon: Network,
    name: "frameio_list_accounts",
    description: "Discovers the Frame.io accounts visible to the connected Adobe identity.",
  },
  {
    icon: Cloud,
    name: "frameio_list_workspaces",
    description: "Lists workspaces for an account so agents can route work through the right organization boundary.",
  },
  {
    icon: ClipboardList,
    name: "frameio_list_projects",
    description: "Lists projects inside a workspace before any delivery or review-link workflow starts.",
  },
  {
    icon: FolderSearch,
    name: "frameio_find_folder",
    description: "Searches project folders by plain-English intent, such as final review, client exports, or selects.",
  },
  {
    icon: UploadCloud,
    name: "frameio_upload_file",
    description: "Creates a V4 local upload, PUTs signed chunks with the expected content type, and returns the uploaded file ID.",
  },
  {
    icon: Link2,
    name: "frameio_create_share",
    description: "Creates public or secure review links for selected Frame.io asset IDs after the destination has been verified.",
  },
];

const workflows = [
  "Resolve delivery target validation before uploading a render",
  "Client/project discovery map across accounts, workspaces, projects, and folders",
  "OAuth or legacy-token health check before review deadlines",
  "Local delivery manifests that bind exports to exact Frame.io destination IDs",
  "Safety gate that summarizes target account, workspace, project, folder, file, and review-link IDs",
  "Foundation for upload, review-link, version-stack, comment-ingest, and Obsidian delivery-log tools",
];

const examplePrompts = [
  "Check Frame.io status and list the accounts, workspaces, and projects Hermes can see.",
  "Find the Frame.io folder for Kelsey final review exports and summarize the destination IDs.",
  "Find the Frame.io project/folder for BBLCO Victoria and compare it to the local NAS ingest structure.",
  "Create a delivery manifest for this Resolve export and the matching Frame.io destination.",
];

function Kicker({ children }: { children: React.ReactNode }) {
  return (
    <p className="font-mono-ui text-[0.65rem] tracking-[0.18em] text-midground/55 uppercase">
      {children}
    </p>
  );
}

export default function FrameioPage() {
  return (
    <div className="flex max-h-[calc(100dvh-6rem)] flex-col gap-5 overflow-y-auto pb-8 pr-1 normal-case lg:max-h-[calc(100dvh-4rem)]">
      <PluginSlot name="frameio:top" />

      <section
        className={cn(
          "relative overflow-hidden border border-midground/20 bg-card/70",
          "px-5 py-6 sm:px-7 sm:py-8",
        )}
        style={{
          clipPath: "var(--component-card-clip-path)",
          borderImage: "var(--component-card-border-image)",
          boxShadow: "var(--component-card-box-shadow)",
        }}
      >
        <div className="absolute -right-20 -top-20 h-56 w-56 rounded-full bg-midground/10 blur-3xl" />
        <div className="relative z-1 grid gap-7 lg:grid-cols-[1.15fr_.85fr] lg:items-end">
          <div className="flex max-w-4xl flex-col gap-5">
            <div className="flex flex-wrap items-center gap-2">
              <Badge tone="outline" className="border-midground/35 bg-midground/5 text-midground">
                Frame.io V4
              </Badge>
              <Badge tone="outline" className="border-midground/35 bg-midground/5 text-midground">
                API uploads + review links
              </Badge>
              <Badge tone="outline" className="border-amber-300/40 bg-amber-300/10 text-amber-200">
                UAT-gated side effects
              </Badge>
            </div>

            <div className="space-y-3">
              <Kicker>Hermes external workflow toolset</Kicker>
              <h1 className="font-expanded text-3xl font-bold leading-[0.95] tracking-[0.04em] text-midground sm:text-5xl uppercase blend-lighter">
                Frame.io routing without browser sessions
              </h1>
              <p className="max-w-3xl text-sm leading-6 tracking-[0.02em] text-midground/70 sm:text-base">
                Hermes can authenticate through Adobe IMS OAuth or a V4 legacy token, discover the real Frame.io account/workspace/project/folder tree, upload assets through signed local-upload URLs, and create review links after destination validation. This is the API-first foundation for safe delivery automation.
              </p>
            </div>
          </div>

          <Card className="bg-background-base/55">
            <CardHeader>
              <CardTitle>Operational posture</CardTitle>
            </CardHeader>
            <CardContent className="grid gap-3 text-sm text-midground/75">
              <div className="flex items-start gap-3">
                <ShieldCheck className="mt-0.5 h-4 w-4 shrink-0 text-emerald-300" />
                <span>Secrets stay in ~/.hermes/.env and are never rendered in tool output.</span>
              </div>
              <div className="flex items-start gap-3">
                <LockKeyhole className="mt-0.5 h-4 w-4 shrink-0 text-emerald-300" />
                <span>Token and cache files live under Hermes home for profile-safe local state.</span>
              </div>
              <div className="flex items-start gap-3">
                <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0 text-emerald-300" />
                <span>Discovery gates future uploads by verifying the destination first.</span>
              </div>
            </CardContent>
          </Card>
        </div>
      </section>

      <section className="grid gap-4 lg:grid-cols-3">
        <Card className="lg:col-span-2">
          <CardHeader>
            <CardTitle>Feature set</CardTitle>
          </CardHeader>
          <CardContent className="grid gap-3 sm:grid-cols-2 xl:grid-cols-3">
            {toolCards.map(({ icon: Icon, name, description }) => (
              <div
                key={name}
                className="flex min-h-40 flex-col gap-3 border border-midground/15 bg-background-base/35 p-4"
              >
                <Icon className="h-5 w-5 text-midground/80" />
                <div className="space-y-2">
                  <h2 className="font-mono-ui text-xs font-bold tracking-[0.08em] text-midground">
                    {name}
                  </h2>
                  <p className="text-xs leading-5 text-midground/62">{description}</p>
                </div>
              </div>
            ))}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Setup surface</CardTitle>
          </CardHeader>
          <CardContent className="flex flex-col gap-4 text-sm text-midground/70">
            <div className="rounded-sm border border-midground/15 bg-black/25 p-4 font-mono-ui text-xs leading-6 text-midground/80">
              <div>FRAMEIO_CLIENT_ID=...</div>
              <div>FRAMEIO_CLIENT_SECRET=...</div>
            </div>
            <p>
              Add rotated Adobe app credentials or a temporary V4 legacy token to ~/.hermes/.env, start a fresh Hermes session, then run the login/status/list sequence.
            </p>
            <div className="grid gap-2 font-mono-ui text-xs text-midground/70">
              <span>frameio_login</span>
              <span>frameio_status</span>
              <span>frameio_list_accounts</span>
              <span>frameio_upload_file</span>
              <span>frameio_create_share</span>
            </div>
          </CardContent>
        </Card>
      </section>

      <section className="grid gap-4 xl:grid-cols-[.9fr_1.1fr]">
        <Card>
          <CardHeader>
            <CardTitle>What this unlocks</CardTitle>
          </CardHeader>
          <CardContent>
            <ul className="grid gap-3 text-sm text-midground/72">
              {workflows.map((workflow) => (
                <li key={workflow} className="flex gap-3">
                  <ArrowRight className="mt-0.5 h-4 w-4 shrink-0 text-midground/55" />
                  <span>{workflow}</span>
                </li>
              ))}
            </ul>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Example asks</CardTitle>
          </CardHeader>
          <CardContent className="grid gap-3">
            {examplePrompts.map((prompt) => (
              <div
                key={prompt}
                className="flex items-start gap-3 border border-midground/15 bg-background-base/35 p-4 text-sm text-midground/75"
              >
                <PlayCircle className="mt-0.5 h-4 w-4 shrink-0 text-midground/65" />
                <span>{prompt}</span>
              </div>
            ))}
          </CardContent>
        </Card>
      </section>

      <section className="grid gap-4 lg:grid-cols-3">
        <Card>
          <CardHeader>
            <CardTitle>Now</CardTitle>
          </CardHeader>
          <CardContent className="text-sm leading-6 text-midground/70">
            Authenticate, inspect access, resolve workspaces/projects/folders, upload files, and create human-verifiable review-link summaries.
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle>Next</CardTitle>
          </CardHeader>
          <CardContent className="text-sm leading-6 text-midground/70">
            Harden resumable upload/error recovery, asset polling, version stacks, comment ingest, and delivery manifest persistence.
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle>Later</CardTitle>
          </CardHeader>
          <CardContent className="text-sm leading-6 text-midground/70">
            Connect Resolve exports, Frame.io review links, Obsidian delivery logs, and client-specific routing rules into one delivery pipeline.
          </CardContent>
        </Card>
      </section>

      <section className="flex flex-col gap-3 border border-midground/15 bg-card/50 p-4 sm:flex-row sm:items-center sm:justify-between">
        <div className="flex items-start gap-3 text-sm text-midground/75">
          <UploadCloud className="mt-0.5 h-4 w-4 shrink-0" />
          <span>
            Upload and share automation must stay gated by destination summaries, regression tests, and recipient-visible UAT before future feature sets ship.
          </span>
        </div>
        <div className="flex items-center gap-2 font-mono-ui text-xs text-midground/55">
          <Link2 className="h-3.5 w-3.5" />
          <span>/frameio</span>
        </div>
      </section>

      <PluginSlot name="frameio:bottom" />
    </div>
  );
}
