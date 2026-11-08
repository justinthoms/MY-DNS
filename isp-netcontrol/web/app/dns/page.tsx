"use client";

import { FormEvent, useState } from "react";
import { post } from "@/lib/api";
import { Alert, LicenseRequired, Shell, useAction, useLoad } from "@/components/ui";
import DomainList from "@/components/DomainList";

export default function DNSPage() {
  const probe = useLoad<unknown>("/dns/allowlist?q=__probe__");
  const act = useAction();
  const [text, setText] = useState("");
  const [category, setCategory] = useState("imported");
  const [key, setKey] = useState(0);
  const importList = async (e: FormEvent) => {
    e.preventDefault();
    let res: any = null;
    if (await act.run(async () => { res = await post("/dns/blocklist/import", { text, category }); })) {
      act.setError("");
      setText("");
      setKey(key + 1);
      alert(`Imported: ${res.added} added, ${res.already_present} already present, ${res.skipped} lines skipped.`);
    }
  };
  const readFile = async (f: File | undefined) => { if (f) setText(await f.text()); };
  return (
    <Shell>
      <h1>DNS filtering</h1>
      {probe.licenseError ? <LicenseRequired message={probe.licenseError} /> : (
        <>
          <DomainList key={`b${key}`} kind="blocklist" />
          <DomainList key={`a${key}`} kind="allowlist" />
          <div className="panel">
            <h2>Import a block list</h2>
            <p className="muted">Paste a list with one domain per line, or a hosts file (<code>0.0.0.0 ads.example.com</code>). Comments (#) and invalid lines are skipped.</p>
            <Alert kind="error">{act.error}</Alert>
            <form className="stack" onSubmit={importList}>
              <input type="file" accept=".txt,.hosts,.list" onChange={(e) => readFile(e.target.files?.[0])} />
              <textarea required value={text} onChange={(e) => setText(e.target.value)} />
              <label>Category<input value={category} onChange={(e) => setCategory(e.target.value)} /></label>
              <div><button disabled={act.busy}>Import</button></div>
            </form>
          </div>
        </>
      )}
    </Shell>
  );
}
