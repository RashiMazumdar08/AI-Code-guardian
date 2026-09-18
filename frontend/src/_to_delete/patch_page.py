import re, sys, io

path = "app/page.tsx"
with io.open(path, "r", encoding="utf-8") as f:
    src = f.read()
orig_len = len(src)

def replace_once(src, old, new, label):
    n = src.count(old)
    if n != 1:
        print(f"FAIL[{label}]: found {n} occurrences (expected 1)")
        sys.exit(1)
    return src.replace(old, new, 1)

def splice_between(src, start_marker, end_marker, label, keep_end=True):
    """Remove everything from start_marker up to (but not including) end_marker."""
    i = src.find(start_marker)
    j = src.find(end_marker)
    if i == -1 or j == -1 or j <= i:
        print(f"FAIL[{label}]: markers not found in order (i={i}, j={j})")
        sys.exit(1)
    return src[:i] + (end_marker if keep_end else "") + src[j + len(end_marker):]

# ---------------------------------------------------------------------
# 1. lucide-react icon imports: add Loader2, Play; drop BarChart2, GitPullRequest
# ---------------------------------------------------------------------
src = replace_once(src,
    '''import {
  Shield,
  Sparkles,
  Download,
  CheckCircle,
  MessageSquare,
  Bot,
  LayoutDashboard,
  Code2,
  Network,
  BarChart2,
  Lock,
  GitPullRequest,
  FileText,
  AlertTriangle,
  ChevronRight,
  Activity,
  Zap,
  PanelLeftClose,
  PanelLeftOpen,
  BookText,
  ChevronDown,
} from "lucide-react";''',
    '''import {
  Shield,
  Sparkles,
  Download,
  CheckCircle,
  MessageSquare,
  Bot,
  LayoutDashboard,
  Code2,
  Network,
  Lock,
  FileText,
  AlertTriangle,
  ChevronRight,
  Activity,
  Zap,
  PanelLeftClose,
  PanelLeftOpen,
  BookText,
  ChevronDown,
  Loader2,
  Play,
} from "lucide-react";''',
    "icon imports")

# ---------------------------------------------------------------------
# 2. Component imports: drop CyberDashboard + direct AgenticScanTab, add
#    AgenticExecutionDrawer + DashboardTab
# ---------------------------------------------------------------------
src = replace_once(src,
    '''import CyberDashboard from "../components/cyberlock/CyberDashboard";
import BusinessIntentPage from "../components/intent/BusinessIntentPage";
import AgenticScanTab from "../components/agentic-scan/AgenticScanTab";
import { useAgenticScan } from "../components/agentic-scan/useAgenticScan";
import AIThreatAnalysisSection from "../components/enrichment/AIThreatAnalysisSection";''',
    '''import BusinessIntentPage from "../components/intent/BusinessIntentPage";
import AgenticExecutionDrawer from "../components/agentic-scan/AgenticExecutionDrawer";
import { useAgenticScan } from "../components/agentic-scan/useAgenticScan";
import AIThreatAnalysisSection from "../components/enrichment/AIThreatAnalysisSection";
import DashboardTab from "../components/dashboard/DashboardTab";''',
    "component imports")

# ---------------------------------------------------------------------
# 3. TABS array -> 6 tabs + removed-tab redirect map
# ---------------------------------------------------------------------
src = replace_once(src,
    '''const TABS = [
  { id: "cyber_dashboard", label: "Dashboard",          icon: LayoutDashboard },
  { id: "workspace",       label: "IDE Workspace",       icon: Code2 },
  { id: "agentic_scan",    label: "Agentic Scan",        icon: Zap },
  { id: "mindmap",         label: "Mind Map",            icon: Network },
  { id: "overview",        label: "Overview",            icon: BarChart2 },
  { id: "security_compliance", label: "Security",        icon: Lock },
  { id: "pr_review",       label: "PR Review",           icon: GitPullRequest },
  { id: "business_intent", label: "Business Intent",     icon: BookText },
  { id: "reports",         label: "Reports",             icon: FileText },
];''',
    '''const TABS = [
  { id: "cyber_dashboard", label: "Dashboard",          icon: LayoutDashboard },
  { id: "workspace",       label: "IDE Workspace",       icon: Code2 },
  { id: "security_compliance", label: "Security",        icon: Lock },
  { id: "business_intent", label: "Business Intent",     icon: BookText },
  { id: "mindmap",         label: "Mind Map",            icon: Network },
  { id: "reports",         label: "Reports",             icon: FileText },
];

// v2.1.0 nav consolidation: Agentic Scan is now a drawer triggered from IDE
// Workspace/Dashboard (see AgenticExecutionDrawer) instead of a standalone
// tab; Overview's content was absorbed into the new Dashboard tab; PR
// Review is parked as future work (see Section 1 of the redesign spec).
// Old deep links to any of these resolve to something sensible instead of
// silently falling through to a 404-ish blank tab.
const REMOVED_TAB_REDIRECTS: Record<string, string> = {
  agentic_scan: "workspace",
  overview: "cyber_dashboard",
  pr_review: "cyber_dashboard",
};''',
    "TABS array")

# ---------------------------------------------------------------------
# 4. getTabFromURL redirect handling
# ---------------------------------------------------------------------
src = replace_once(src,
    '''  const getTabFromURL = useCallback(() => {
    const t = searchParams?.get("tab");
    return TABS.some((x) => x.id === t) ? t! : "cyber_dashboard";
  }, [searchParams]);''',
    '''  const getTabFromURL = useCallback(() => {
    const t = searchParams?.get("tab");
    if (t && REMOVED_TAB_REDIRECTS[t]) return REMOVED_TAB_REDIRECTS[t];
    return TABS.some((x) => x.id === t) ? t! : "cyber_dashboard";
  }, [searchParams]);''',
    "getTabFromURL redirect")

# ---------------------------------------------------------------------
# 5. navigateTo stays as-is; add agenticDrawerOpen + closeAgenticDrawer
#    right after navigateTo's definition.
# ---------------------------------------------------------------------
src = replace_once(src,
    '''      router.push(`?${params.toString()}`);
    },
    [router, searchParams]
  );''',
    '''      router.push(`?${params.toString()}`);
    },
    [router, searchParams]
  );

  /* Agentic Execution drawer open state -- URL-param driven (like every
     other deep link in this file) so browser back/forward and shareable
     links behave consistently. Closing uses an explicit param list rather
     than navigateTo (which only ADDS params) so agentic/sub/finding are
     actually dropped, not left dangling in the URL. */
  const agenticDrawerOpen = searchParams?.get("agentic") === "1";
  const closeAgenticDrawer = useCallback(() => {
    router.push(`?${new URLSearchParams({ tab: "workspace" }).toString()}`);
  }, [router]);''',
    "agenticDrawerOpen/closeAgenticDrawer")

# ---------------------------------------------------------------------
# 6. viewFindingTrace -> opens drawer over current tab instead of
#    navigating to the removed "agentic_scan" tab.
# ---------------------------------------------------------------------
src = replace_once(src,
    '''  const viewFindingTrace = useCallback((findingId: string) => {
    navigateTo("agentic_scan", { sub: "evidence", finding: findingId });
  }, [navigateTo]);''',
    '''  const viewFindingTrace = useCallback((findingId: string) => {
    navigateTo(activeTab, { agentic: "1", sub: "evidence", finding: findingId });
  }, [navigateTo, activeTab]);''',
    "viewFindingTrace")

# ---------------------------------------------------------------------
# 7. runAgenticForCurrentScan -> open drawer instead of navigating to the
#    removed "agentic_scan" tab.
# ---------------------------------------------------------------------
src = replace_once(src,
    '''    agentic.start({ scanId: currentScanId, scanMode: "full_scan" });
    navigateTo("agentic_scan");
  }, [currentScanId, agentic, navigateTo]);''',
    '''    agentic.start({ scanId: currentScanId, scanMode: "full_scan" });
    // Opens the Agentic Execution drawer over whichever tab the person is
    // currently on (see AgenticExecutionDrawer) instead of navigating to a
    // standalone tab, which the v2.1.0 nav consolidation removed.
    navigateTo(activeTab, { agentic: "1" });
  }, [currentScanId, agentic, navigateTo, activeTab]);''',
    "runAgenticForCurrentScan")

# ---------------------------------------------------------------------
# 8. Notification-badge state (Section 8): unseen AI-result flags, edge-
#    triggered together with the existing toast, cleared on tab visit.
# ---------------------------------------------------------------------
src = replace_once(src,
    '''  const prevAgenticStatusRef = React.useRef(agentic.workflowStatus);
  useEffect(() => {
    if (prevAgenticStatusRef.current !== "completed" && agentic.workflowStatus === "completed") {
      setToast("Agentic analysis complete. View AI threat analysis in Security tab and business impact in Business Intent tab.");
      const t = setTimeout(() => setToast(null), 6000);
      prevAgenticStatusRef.current = agentic.workflowStatus;
      return () => clearTimeout(t);
    }
    prevAgenticStatusRef.current = agentic.workflowStatus;
  }, [agentic.workflowStatus]);''',
    '''  const prevAgenticStatusRef = React.useRef(agentic.workflowStatus);
  // Notification badges (Section 8): a completed run marks Security and
  // Business Intent as having unseen AI results; visiting either tab marks
  // it read. Reset (not just set) on every fresh completion so a second
  // run re-flags a tab the user already saw the first run's results in.
  const [securityAiUnseen, setSecurityAiUnseen] = useState(false);
  const [businessAiUnseen, setBusinessAiUnseen] = useState(false);
  useEffect(() => {
    if (prevAgenticStatusRef.current !== "completed" && agentic.workflowStatus === "completed") {
      setToast("Agentic analysis complete. View AI threat analysis in Security tab and business impact in Business Intent tab.");
      setSecurityAiUnseen(true);
      setBusinessAiUnseen(true);
      const t = setTimeout(() => setToast(null), 6000);
      prevAgenticStatusRef.current = agentic.workflowStatus;
      return () => clearTimeout(t);
    }
    prevAgenticStatusRef.current = agentic.workflowStatus;
  }, [agentic.workflowStatus]);

  useEffect(() => {
    if (activeTab === "security_compliance") setSecurityAiUnseen(false);
    if (activeTab === "business_intent") setBusinessAiUnseen(false);
  }, [activeTab]);''',
    "notification badge state")

with io.open(path, "w", encoding="utf-8") as f:
    f.write(src)

print(f"OK: wrote {path} ({orig_len} -> {len(src)} bytes)")
