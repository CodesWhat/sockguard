import { Icon } from "@/components/icon";
import { type Milestone, roadmap } from "@/lib/site-content";

// Roadmap = git-log style rail, newest first, planned rows on top. Released =
// filled node, HEAD highlighted, planned = dashed node. The default view is
// every planned row, HEAD, and the four released rows before it; older
// releases fold into one native <details> that continues the same rail.

const RECENT_RELEASES_SHOWN = 4;

const newestFirst = [...roadmap].reverse();
const headVersion = roadmap.filter((m) => m.status === "released").at(-1)?.version;

export const roadmapHasPlanned = roadmap.some((m) => m.status !== "released");

function Row({ m, first }: { m: Milestone; first?: boolean }) {
  const released = m.status === "released";
  const isHead = m.version === headVersion;
  const shown = m.items.slice(0, 2);
  const rest = m.items.slice(2);
  const node = isHead ? "head" : released ? "rel" : "plan";

  return (
    <li className={`row${first ? " first" : ""}${released ? "" : " plannedrow"}`}>
      <div className="rail">
        <i className={`node ${node}`} />
      </div>
      <div className="body">
        <div className="hd">
          <span className="v">{m.version}</span>
          {isHead ? <span className="chip nocase t-primary">HEAD -&gt; {m.version}</span> : null}
          <span className="tt">
            {m.emoji} {m.title}
          </span>
        </div>
        {shown.map((item) => (
          <span className="it" key={item}>
            {item}
          </span>
        ))}
        {rest.length > 0 ? (
          <details>
            <summary data-n={rest.length} />
            {rest.map((item) => (
              <span className="it" key={item}>
                {item}
              </span>
            ))}
          </details>
        ) : null}
      </div>
    </li>
  );
}

const Root = () => (
  <li className="row root">
    <div className="rail">
      <i className="node rel" style={{ opacity: 0.5 }} />
    </div>
    <div className="body">└ (initial commit)</div>
  </li>
);

export function RoadmapLog() {
  const headIdx = newestFirst.findIndex((m) => m.version === headVersion);
  const visibleEnd = headIdx + 1 + RECENT_RELEASES_SHOWN;
  const visible = newestFirst.slice(0, visibleEnd);
  const older = newestFirst.slice(visibleEnd);

  return (
    <>
      {/* biome-ignore lint/a11y/useSemanticElements: a legend row, not a form control group */}
      <div className="legend" role="group" aria-label="Legend">
        <span>
          <i className="node rel" />
          Released
        </span>
        <span>
          <i className="node head" />
          Current (HEAD)
        </span>
        {roadmapHasPlanned ? (
          <span>
            <i className="node plan" />
            Planned
          </span>
        ) : null}
      </div>
      <div className="log">
        <div className="logh">
          <Icon name="git-branch" />
          <b>roadmap</b>
          <span>git log --graph</span>
        </div>
        <ol className="rows">
          {visible.map((m, i) => (
            <Row key={m.version} m={m} first={i === 0} />
          ))}
          {older.length > 0 ? (
            <li className="rfold">
              <details className="older">
                <summary data-n={older.length}>
                  <span className="rail" aria-hidden="true" />
                </summary>
                <ol className="rows sub">
                  {older.map((m) => (
                    <Row key={m.version} m={m} />
                  ))}
                  <Root />
                </ol>
              </details>
            </li>
          ) : (
            <Root />
          )}
        </ol>
      </div>
    </>
  );
}
