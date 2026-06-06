import { useState } from "react";
import ResultCard from "./components/ResultCard";

// We use a relative URL so Vite can proxy requests to Django during development.
const API_URL = "/api/lookup/";

function getDashboardSummary(result) {
  const sourceList = Object.values(result.sources);
  const successfulSources = sourceList.filter((source) => source.ok).length;
  const applicableSources = sourceList.filter((source) => {
    return !source.message.toLowerCase().includes("only used for");
  }).length;

  const virusTotalData = result.sources.virustotal?.data?.data?.attributes;
  const abuseIpDbData = result.sources.abuseipdb?.data?.data;

  const maliciousCount = virusTotalData?.last_analysis_stats?.malicious ?? 0;
  const suspiciousCount = virusTotalData?.last_analysis_stats?.suspicious ?? 0;
  const harmlessCount = virusTotalData?.last_analysis_stats?.harmless ?? 0;
  const abuseConfidenceScore = abuseIpDbData?.abuseConfidenceScore ?? "N/A";

  let headline = "Lookup finished successfully.";
  let tone = "neutral";

  if (maliciousCount > 0 || suspiciousCount > 0) {
    headline = "This indicator may need more attention.";
    tone = "warning";
  } else if (successfulSources > 0) {
    headline = "No strong warning signs were returned by the successful sources.";
    tone = "good";
  }

  return {
    headline,
    tone,
    successfulSources,
    applicableSources,
    maliciousCount,
    suspiciousCount,
    harmlessCount,
    abuseConfidenceScore,
  };
}

function getIpOverview(result) {
  const ipApiData = result.sources.ip_api?.data;
  const ipapiIsData = result.sources.ipapi_is?.data;
  const abuseIpDbData = result.sources.abuseipdb?.data?.data;

  const isVpn = Boolean(ipapiIsData?.is_vpn);
  const isProxy = Boolean(ipapiIsData?.is_proxy || ipApiData?.proxy);
  const isHosting = Boolean(ipapiIsData?.is_datacenter || ipApiData?.hosting);
  const isTor = Boolean(ipapiIsData?.is_tor);

  let verdict = "No strong VPN signal found.";
  let tone = "good";

  if (isVpn || isProxy || isTor) {
    verdict = "This IP looks like it may be anonymized or relayed.";
    tone = "warning";
  } else if (isHosting) {
    verdict = "This IP does not look like a VPN, but it may belong to hosting infrastructure.";
    tone = "neutral";
  }

  return {
    verdict,
    tone,
    isVpn,
    isProxy,
    isHosting,
    isTor,
    organization: ipapiIsData?.company?.name || ipApiData?.org || abuseIpDbData?.isp || "Unknown",
    country: ipapiIsData?.location?.country || ipApiData?.country || abuseIpDbData?.countryCode || "Unknown",
  };
}

function getDomainOverview(result) {
  const rdapData = result.sources.rdap?.data;
  const dnsData = result.sources.dns_google?.data ?? {};
  const hostFromUrl = result.input_type === "url" ? new URL(result.normalized_input).hostname : result.normalized_input;
  const domainName = rdapData?.ldhName || rdapData?.unicodeName || hostFromUrl;
  const nameservers = (rdapData?.nameservers || [])
    .map((server) => server?.ldhName || server?.unicodeName)
    .filter(Boolean);
  const statuses = (rdapData?.status || []).filter(Boolean);
  const events = rdapData?.events || [];

  const creationEvent = events.find((event) => event.eventAction === "registration");
  const updateEvent = events.find((event) => event.eventAction === "last changed");
  const expirationEvent = events.find((event) => event.eventAction === "expiration");

  const aRecords = dnsData.A?.data?.Answer || [];
  const mxRecords = dnsData.MX?.data?.Answer || [];
  const txtRecords = dnsData.TXT?.data?.Answer || [];

  return {
    domainName,
    hostFromUrl,
    exists: result.sources.rdap?.ok || result.sources.dns_google?.ok,
    nameservers,
    statuses,
    createdOn: creationEvent?.eventDate,
    updatedOn: updateEvent?.eventDate,
    expiresOn: expirationEvent?.eventDate,
    aRecordCount: aRecords.length,
    mxRecordCount: mxRecords.length,
    txtRecordCount: txtRecords.length,
    handle: rdapData?.handle || "Not available",
  };
}

function App() {
  const [value, setValue] = useState("");
  const [result, setResult] = useState(null);
  const [error, setError] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const sampleInputs = ["8.8.8.8", "example.com", "https://example.com/login"];

  async function handleSubmit(event) {
    event.preventDefault();

    setIsLoading(true);
    setError("");
    setResult(null);

    try {
      const response = await fetch(API_URL, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ value }),
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.value?.[0] || "Something went wrong while talking to the backend.");
      }

      setResult(data);
    } catch (requestError) {
      setError(requestError.message);
    } finally {
      setIsLoading(false);
    }
  }

  const sourceEntries = result ? Object.entries(result.sources) : [];
  const dashboardSummary = result ? getDashboardSummary(result) : null;
  const ipOverview =
    result && result.input_type === "ip"
      ? getIpOverview(result)
      : null;
  const domainOverview =
    result && result.input_type !== "ip"
      ? getDomainOverview(result)
      : null;

  return (
    <div className="page-shell">
      <div className="hero-panel">
        <p className="eyebrow">ThreatLookup App</p>

        <form className="lookup-form" onSubmit={handleSubmit}>
          <label htmlFor="lookup-input">Lookup value</label>
          <div className="lookup-input-row">
            <input
              id="lookup-input"
              type="text"
              placeholder="Examples: 8.8.8.8, example.com, https://example.com/login"
              value={value}
              onChange={(event) => setValue(event.target.value)}
            />
            <button type="submit" disabled={isLoading}>
              {isLoading ? "Looking up..." : "Run Lookup"}
            </button>
          </div>

          <div className="sample-row" aria-label="Example lookups">
            {sampleInputs.map((sample) => (
              <button
                key={sample}
                type="button"
                className="sample-chip"
                onClick={() => setValue(sample)}
              >
                {sample}
              </button>
            ))}
          </div>
        </form>

        {error ? <div className="error-box">{error}</div> : null}
      </div>

      {result ? (
        <section className="results-area">
          <div className="results-heading">
            <div>
              <p className="section-label">Results</p>
              <h2 className="results-title">Lookup overview for {result.normalized_input}</h2>
            </div>
          </div>

          <div className={`summary-card verdict-card verdict-${dashboardSummary.tone}`}>
            <div className="verdict-header">
              <div>
                <p className="section-label">Overall Result</p>
                <h2>{dashboardSummary.headline}</h2>
              </div>
              <div className="verdict-score">
                <span className="score-number">{dashboardSummary.maliciousCount}</span>
                <span className="score-label">Malicious flags</span>
              </div>
            </div>

            <div className="metric-grid">
              <div className="metric-card">
                <span className="metric-label">Input checked</span>
                <strong>{result.normalized_input}</strong>
              </div>
              <div className="metric-card">
                <span className="metric-label">Detected type</span>
                <strong>{result.input_type.toUpperCase()}</strong>
              </div>
              <div className="metric-card">
                <span className="metric-label">Successful sources</span>
                <strong>
                  {dashboardSummary.successfulSources} / {dashboardSummary.applicableSources}
                </strong>
              </div>
              <div className="metric-card">
                <span className="metric-label">AbuseIPDB score</span>
                <strong>{dashboardSummary.abuseConfidenceScore}</strong>
              </div>
              <div className="metric-card">
                <span className="metric-label">VirusTotal malicious</span>
                <strong>{dashboardSummary.maliciousCount}</strong>
              </div>
              <div className="metric-card">
                <span className="metric-label">VirusTotal suspicious</span>
                <strong>{dashboardSummary.suspiciousCount}</strong>
              </div>
            </div>
          </div>

          {ipOverview ? (
            <div className={`summary-card domain-overview-card verdict-${ipOverview.tone}`}>
              <div className="overview-header">
                <div>
                  <p className="section-label">IP Privacy Overview</p>
                  <h2>{result.normalized_input}</h2>
                  <p className="verdict-copy">{ipOverview.verdict}</p>
                </div>
                <span className={`overview-badge ${ipOverview.isVpn || ipOverview.isProxy || ipOverview.isTor ? "missing" : "exists"}`}>
                  {ipOverview.isVpn ? "VPN likely" : ipOverview.isProxy ? "Proxy likely" : ipOverview.isTor ? "Tor likely" : "No VPN signal"}
                </span>
              </div>

              <div className="domain-facts-grid">
                <div className="metric-card">
                  <span className="metric-label">VPN</span>
                  <strong>{ipOverview.isVpn ? "Yes" : "No"}</strong>
                </div>
                <div className="metric-card">
                  <span className="metric-label">Proxy</span>
                  <strong>{ipOverview.isProxy ? "Yes" : "No"}</strong>
                </div>
                <div className="metric-card">
                  <span className="metric-label">Hosting / Datacenter</span>
                  <strong>{ipOverview.isHosting ? "Yes" : "No"}</strong>
                </div>
                <div className="metric-card">
                  <span className="metric-label">Tor</span>
                  <strong>{ipOverview.isTor ? "Yes" : "No"}</strong>
                </div>
                <div className="metric-card">
                  <span className="metric-label">Organization</span>
                  <strong>{ipOverview.organization}</strong>
                </div>
                <div className="metric-card">
                  <span className="metric-label">Country</span>
                  <strong>{ipOverview.country}</strong>
                </div>
              </div>
            </div>
          ) : null}

          {domainOverview ? (
            <div className="summary-card domain-overview-card">
              <div className="overview-header">
                <div>
                  <p className="section-label">Domain Overview</p>
                  <h2>{domainOverview.domainName}</h2>
                  <p className="verdict-copy">
                    {domainOverview.exists
                      ? "This domain appears to exist because we found registration or DNS information for it."
                      : "We could not confirm the domain with the current sources."}
                  </p>
                </div>
                <span className={`overview-badge ${domainOverview.exists ? "exists" : "missing"}`}>
                  {domainOverview.exists ? "Domain found" : "Not confirmed"}
                </span>
              </div>

              <div className="domain-facts-grid">
                <div className="metric-card">
                  <span className="metric-label">Host checked</span>
                  <strong>{domainOverview.hostFromUrl}</strong>
                </div>
                <div className="metric-card">
                  <span className="metric-label">RDAP handle</span>
                  <strong>{domainOverview.handle}</strong>
                </div>
                <div className="metric-card">
                  <span className="metric-label">A records</span>
                  <strong>{domainOverview.aRecordCount}</strong>
                </div>
                <div className="metric-card">
                  <span className="metric-label">MX records</span>
                  <strong>{domainOverview.mxRecordCount}</strong>
                </div>
                <div className="metric-card">
                  <span className="metric-label">TXT records</span>
                  <strong>{domainOverview.txtRecordCount}</strong>
                </div>
                <div className="metric-card">
                  <span className="metric-label">Created on</span>
                  <strong>{domainOverview.createdOn || "Not available"}</strong>
                </div>
              </div>

              <div className="overview-columns">
                <div className="overview-panel">
                  <h3>Nameservers</h3>
                  {domainOverview.nameservers.length > 0 ? (
                    <div className="chip-list">
                      {domainOverview.nameservers.map((server) => (
                        <span key={server} className="info-chip">
                          {server}
                        </span>
                      ))}
                    </div>
                  ) : (
                    <p className="muted-text">No nameservers were returned.</p>
                  )}
                </div>

                <div className="overview-panel">
                  <h3>Registration status</h3>
                  {domainOverview.statuses.length > 0 ? (
                    <div className="chip-list">
                      {domainOverview.statuses.map((status) => (
                        <span key={status} className="info-chip">
                          {status}
                        </span>
                      ))}
                    </div>
                  ) : (
                    <p className="muted-text">No status values were returned.</p>
                  )}
                </div>
              </div>
            </div>
          ) : null}

          <div className="card-grid">
            {sourceEntries.map(([sourceKey, sourceValue]) => (
              <ResultCard key={sourceKey} title={sourceValue.source} result={sourceValue} />
            ))}
          </div>
        </section>
      ) : null}
    </div>
  );
}

export default App;
