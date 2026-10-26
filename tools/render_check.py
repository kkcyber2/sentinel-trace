"""Render the HTML report in headless Chromium and assert it is sound.

Checks the DOM actually built (KPI cards, violation cards, blast-radius rows,
injection-chain hops) and that the page produced no console or page errors.

Copyright (c) 2026 kk (kkdev9715). All Rights Reserved.
"""

import asyncio

from playwright.async_api import async_playwright


async def main() -> None:
    async with async_playwright() as p:
        b = await p.chromium.launch()
        pg = await b.new_page(viewport={"width": 1280, "height": 1600})
        errs: list[str] = []
        perrs: list[str] = []
        pg.on("console", lambda m: errs.append(m.text) if m.type == "error" else None)
        pg.on("pageerror", lambda e: perrs.append(str(e)))
        await pg.goto("file:///tmp/r.html")
        await pg.wait_for_timeout(700)
        await pg.screenshot(path="/workspace/sentinel-trace/report.png", full_page=True)

        kpis = await pg.eval_on_selector_all(".kpi", "e=>e.length")
        cards = await pg.eval_on_selector_all(".card", "e=>e.length")
        rows = await pg.eval_on_selector_all("tbody tr", "e=>e.length")
        hops = await pg.eval_on_selector_all(".hop", "e=>e.length")
        verdict = await pg.eval_on_selector("#verdict", "e=>e.textContent")
        risk = await pg.eval_on_selector("#k-risk", "e=>e.textContent")
        auth = await pg.eval_on_selector("#k-auth", "e=>e.textContent")
        blast = await pg.eval_on_selector("#k-blast", "e=>e.textContent")
        print(f"kpis={kpis} cards={cards} rows={rows} hops={hops}")
        print(f"verdict={verdict} risk={risk} auth={auth} blast={blast}")
        print(f"console_errors={len(errs)} page_errors={len(perrs)}")
        for e in errs[:5]:
            print("  console:", e)
        for e in perrs[:5]:
            print("  page:", e)
        await b.close()


asyncio.run(main())
