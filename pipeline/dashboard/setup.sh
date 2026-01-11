#!/bin/bash

# CVE Pipeline Dashboard Setup Script
echo "🚀 Setting up CVE Pipeline Dashboard..."

# Navigate to dashboard directory
cd "$(dirname "$0")"

# Check if node is installed
if ! command -v node &> /dev/null; then
    echo "❌ Node.js is not installed. Please install Node.js 18+ and try again."
    exit 1
fi

echo "✅ Node.js version: $(node --version)"

# Install server dependencies
echo "📦 Installing server dependencies..."
npm install

# Install client dependencies
echo "📦 Installing client dependencies..."
cd client
npm install
cd ..

echo ""
echo "✅ Setup complete!"
echo ""
echo "To start the dashboard, run:"
echo "  cd dashboard"
echo "  npm run dev"
echo ""
echo "Then open http://localhost:5173 in your browser."
