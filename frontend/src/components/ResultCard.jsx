function ResultCard({ title, result }) {
  const prettyData = result.data ? JSON.stringify(result.data, null, 2) : "No data returned.";
  const lowerMessage = result.message.toLowerCase();

  // We separate "not applicable" from "real error" so the UI feels more natural.
  let statusLabel = "Needs attention";
  let statusClass = "warning";
  let summaryText = result.message;

  if (result.ok) {
    statusLabel = "Success";
    statusClass = "success";
  } else if (lowerMessage.includes("only used for")) {
    statusLabel = "Not applicable";
    statusClass = "neutral";
    summaryText = "This source does not apply to this kind of input, so it was skipped on purpose.";
  } else if (result.status_code === 404) {
    statusLabel = "No data found";
    statusClass = "neutral";
    summaryText = "The source responded correctly, but it does not currently have a record for this value.";
  } else if (result.status_code === 401 || result.status_code === 403) {
    statusLabel = "Access limited";
    statusClass = "neutral";
    summaryText = "This source needs authentication or denied the request for this lookup, so the app could not read more data from it.";
  } else if (result.status_code === 429) {
    statusLabel = "Rate limited";
    statusClass = "neutral";
    summaryText = "This source is temporarily limiting requests. You can try again later.";
  } else if (result.status_code === 500 || result.status_code === 502 || result.status_code === 503) {
    statusLabel = "Source issue";
    statusClass = "neutral";
    summaryText = "This source appears to be having a temporary server-side problem right now.";
  } else if (lowerMessage.includes("missing")) {
    statusLabel = "Missing key";
    statusClass = "warning";
  }

  const highlightItems = [];

  if (title === "VirusTotal") {
    const stats = result.data?.data?.attributes?.last_analysis_stats;
    if (stats) {
      highlightItems.push(`Malicious: ${stats.malicious ?? 0}`);
      highlightItems.push(`Suspicious: ${stats.suspicious ?? 0}`);
      highlightItems.push(`Undetected: ${stats.undetected ?? 0}`);
    }
  }

  if (title === "AbuseIPDB") {
    const abuseData = result.data?.data;
    if (abuseData) {
      highlightItems.push(`Abuse score: ${abuseData.abuseConfidenceScore ?? "N/A"}`);
      highlightItems.push(`Country: ${abuseData.countryCode ?? "N/A"}`);
      highlightItems.push(`ISP: ${abuseData.isp ?? "N/A"}`);
    }
  }

  if (title === "Shodan InternetDB") {
    const shodanData = result.data;
    if (shodanData?.ports) {
      highlightItems.push(`Open ports: ${shodanData.ports.join(", ") || "None"}`);
    }
    if (shodanData?.hostnames?.length) {
      highlightItems.push(`Hostnames: ${shodanData.hostnames.join(", ")}`);
    }
  }

  if (title === "GreyNoise Community") {
    const greyNoiseData = result.data;
    if (greyNoiseData) {
      highlightItems.push(`Classification: ${greyNoiseData.classification ?? "Unknown"}`);
      highlightItems.push(`Noise: ${greyNoiseData.noise ? "Yes" : "No"}`);
      highlightItems.push(`RIOT: ${greyNoiseData.riot ? "Yes" : "No"}`);
    }
  }

  if (title === "ThreatFox") {
    const firstMatch = result.data?.data?.[0];
    const hasMatch = Boolean(firstMatch);
    highlightItems.push(`Threat match found: ${hasMatch ? "Yes" : "No"}`);
    highlightItems.push(`Known malware listed: ${firstMatch?.malware_printable ? "Yes" : "No"}`);
    highlightItems.push(`IOC match found: ${hasMatch ? "Yes" : "No"}`);
  }

  if (title === "URLHaus") {
    const queryStatus = result.data?.query_status;
    const hasMatch = queryStatus && queryStatus !== "no_results";
    highlightItems.push(`URL match found: ${hasMatch ? "Yes" : "No"}`);
    highlightItems.push(`Known malicious URL: ${hasMatch ? "Yes" : "No"}`);
  }

  if (title === "RDAP") {
    const rdapData = result.data;
    if (rdapData?.ldhName) {
      highlightItems.push(`Name: ${rdapData.ldhName}`);
    }
    if (rdapData?.handle) {
      highlightItems.push(`Handle: ${rdapData.handle}`);
    }
    if (rdapData?.port43) {
      highlightItems.push(`WHOIS server: ${rdapData.port43}`);
    }
  }

  if (title === "IP-API") {
    const ipApiData = result.data;
    if (ipApiData) {
      highlightItems.push(`Proxy: ${ipApiData.proxy ? "Yes" : "No"}`);
      highlightItems.push(`Hosting: ${ipApiData.hosting ? "Yes" : "No"}`);
      highlightItems.push(`ISP: ${ipApiData.isp ?? "Unknown"}`);
    }
  }

  if (title === "ipapi.is") {
    const ipapiIsData = result.data;
    if (ipapiIsData) {
      highlightItems.push(`VPN: ${ipapiIsData.is_vpn ? "Yes" : "No"}`);
      highlightItems.push(`Proxy: ${ipapiIsData.is_proxy ? "Yes" : "No"}`);
      highlightItems.push(`Datacenter: ${ipapiIsData.is_datacenter ? "Yes" : "No"}`);
    }
  }

  return (
    <article className="result-card">
      <div className="card-header">
        <div>
          <p className="card-eyebrow">Source</p>
          <h3>{title}</h3>
        </div>
        <span className={`status-pill ${statusClass}`}>{statusLabel}</span>
      </div>

      <p className="message-text">{summaryText}</p>

      {result.status_code ? (
        <p className="status-code">
          <strong>HTTP status:</strong> {result.status_code}
        </p>
      ) : null}

      {highlightItems.length > 0 ? (
        <div className="highlight-list">
          {highlightItems.map((item) => (
            <div key={item} className="highlight-item">
              <span className="highlight-dot" />
              <span>{item}</span>
            </div>
          ))}
        </div>
      ) : null}

      <details className="json-details">
        <summary>View raw JSON</summary>
        <div className="json-block">
          <pre>{prettyData}</pre>
        </div>
      </details>
    </article>
  );
}

export default ResultCard;
