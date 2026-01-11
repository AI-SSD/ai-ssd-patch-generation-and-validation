# CVE Pipeline Dashboard

A comprehensive React + Node.js dashboard for analyzing CVE patch generation pipeline results from your dissertation research.

## Features

- **Dashboard Overview**: High-level statistics including total runs, success rates, and execution times
- **Issue Flagging**: Major issues (failed phases, PoC still works, build failures) highlighted in red
- **Validations**: Detailed table view with filtering by CVE, model, status, and more
- **CVE Analysis**: Per-vulnerability breakdown with success rates and model comparisons
- **Model Analysis**: LLM model performance comparison with execution time analysis
- **Patch Generation**: View all generated patches with syntax validation status
- **Feedback Loop**: Iterative retry history and patch refinement tracking
- **SAST Findings**: Static analysis results from cppcheck, flawfinder, and rats

## Tech Stack

- **Frontend**: React 18, Vite, Tailwind CSS, Recharts
- **Backend**: Node.js, Express
- **Styling**: Dark mode aesthetic with Tailwind CSS

## Project Structure

```
dashboard/
├── package.json          # Root package.json with scripts
├── server/
│   ├── index.js         # Express server with API endpoints
│   └── dataParser.js    # Data ingestion and parsing logic
└── client/
    ├── package.json
    ├── vite.config.js
    ├── tailwind.config.js
    ├── index.html
    └── src/
        ├── main.jsx
        ├── App.jsx
        ├── index.css
        ├── api.js           # API client
        ├── components/
        │   ├── Sidebar.jsx
        │   ├── StatCard.jsx
        │   ├── IssueCard.jsx
        │   ├── DataTable.jsx
        │   ├── StatusBadge.jsx
        │   └── FilterBar.jsx
        └── pages/
            ├── Dashboard.jsx
            ├── Validations.jsx
            ├── CVEAnalysis.jsx
            ├── ModelAnalysis.jsx
            ├── Patches.jsx
            ├── FeedbackLoop.jsx
            └── SastFindings.jsx
```

## Installation

1. Install all dependencies:
```bash
cd dashboard
npm run install:all
```

Or install separately:
```bash
# Install server dependencies
npm install

# Install client dependencies
cd client && npm install
```

2. Start the development servers:
```bash
npm run dev
```

This will start:
- Backend server on http://localhost:3001
- Frontend dev server on http://localhost:5173

## API Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /api/overview` | Dashboard overview statistics |
| `GET /api/issues` | All flagged issues (major/warning) |
| `GET /api/validations` | Validation results with optional filters |
| `GET /api/cves` | CVE-specific statistics |
| `GET /api/models` | Model performance statistics |
| `GET /api/phases` | Pipeline phase execution data |
| `GET /api/feedback-loop` | Feedback loop retry results |
| `GET /api/sast-findings` | SAST tool findings |
| `GET /api/charts/:type` | Chart data (success-by-model, success-by-cve, execution-time, sast-by-tool, timeline, retry-analysis) |
| `GET /api/patches` | Patch generation results |
| `GET /api/reproductions` | Vulnerability reproduction results |
| `POST /api/refresh` | Refresh data cache |

## Data Sources

The dashboard automatically parses data from:
- `results/` - Pipeline run results, feedback loop results
- `validation_results/` - Validation summaries and individual validation files
- `patches/` - Patch generation results and response metadata

## Issue Flagging Logic

Issues are flagged as **Major** (red) when:
- A pipeline phase fails
- PoC exploit still works after patching
- Build compilation fails
- Patch marked as "unpatchable" after all retries

Issues are flagged as **Warning** (yellow) when:
- SAST analysis finds potential issues

## Filtering Options

The Validations page supports filtering by:
- CVE ID
- Model name
- Status (Success, PoC Still Works)
- PoC Blocked (true/false)
- SAST Passed (true/false)

## Screenshots

The dashboard features:
- Dark mode UI with a sidebar navigation
- Interactive charts using Recharts
- Responsive design for various screen sizes
- Modal dialogs for detailed views

## Development

To modify the dashboard:

1. **Backend changes**: Edit `server/index.js` or `server/dataParser.js`
2. **Frontend changes**: Edit files in `client/src/`
3. **Styling**: Uses Tailwind CSS classes

The frontend proxies API requests to the backend during development (configured in `vite.config.js`).

## Building for Production

```bash
cd dashboard
npm run build
```

This creates a production build in `client/dist/`.
