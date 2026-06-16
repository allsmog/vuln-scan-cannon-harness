# Task: research known vulnerabilities for this stack

Below are the project's dependencies. Research known CVEs, security advisories, and classic footgun patterns for these specific libraries (and versions, where given), and turn the most relevant into **targeted hunts** cannon can run against the code. Prefer libraries with known-dangerous APIs or recent advisories at these versions.

## Dependencies

{dependencies}

## How

For each worthwhile hunt, give: the **bug class**, the **library**, a one-line **hint** describing the vulnerable usage to look for in the code, and a **weight 0..1** (how worth hunting — higher for severe, version-confirmed, or easily-misused issues). Skip libraries with no meaningful security history. Don't invent CVEs; if unsure, lower the weight.

## Output (one block per hunt)

<hunt>bug class | library | one-line hint on the vulnerable usage to look for | weight 0..1</hunt>

Example:
<hunt>prototype pollution | lodash | _.merge / _.set with attacker-controlled keys reaching Object.prototype | 0.8</hunt>
