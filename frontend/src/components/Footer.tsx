"use client";

import { ShieldLogo } from "./ShieldLogo";
import { Github, Twitter, ExternalLink } from "lucide-react";

export function Footer() {
  return (
    <footer className="border-t border-frost-dark-800 bg-frost-dark-900/50">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-12">
        <div className="grid grid-cols-1 md:grid-cols-4 gap-8">
          {/* Brand */}
          <div className="col-span-1 md:col-span-2">
            <ShieldLogo size="sm" showText={true} />
            <p className="mt-4 text-frost-dark-400 text-sm max-w-md">
              High-isolation training scenarios with deterministic scoring.
              Build real skills. Get certified. Prove your worth.
            </p>
            <div className="flex items-center gap-4 mt-6">
              <a
                href="#"
                className="text-frost-dark-500 hover:text-frost-dark-300 transition-colors"
              >
                <Github size={20} />
              </a>
              <a
                href="#"
                className="text-frost-dark-500 hover:text-frost-dark-300 transition-colors"
              >
                <Twitter size={20} />
              </a>
            </div>
          </div>

          {/* Training Tracks */}
          <div>
            <h4 className="font-display font-semibold text-frost-dark-200 uppercase tracking-wider text-sm mb-4">
              Tracks
            </h4>
            <ul className="space-y-2">
              <li>
                <a href="#" className="text-frost-dark-400 hover:text-frost-orange-400 text-sm transition-colors">
                  Network+ (NetPlus)
                </a>
              </li>
              <li>
                <a href="#" className="text-frost-dark-400 hover:text-frost-orange-400 text-sm transition-colors">
                  CCNA
                </a>
              </li>
              <li>
                <a href="#" className="text-frost-dark-400 hover:text-frost-orange-400 text-sm transition-colors">
                  CISSP
                </a>
              </li>
            </ul>
          </div>

          {/* Resources */}
          <div>
            <h4 className="font-display font-semibold text-frost-dark-200 uppercase tracking-wider text-sm mb-4">
              Resources
            </h4>
            <ul className="space-y-2">
              <li>
                <a href="#" className="text-frost-dark-400 hover:text-frost-orange-400 text-sm transition-colors inline-flex items-center gap-1">
                  Documentation
                  <ExternalLink size={12} />
                </a>
              </li>
              <li>
                <a href="#" className="text-frost-dark-400 hover:text-frost-orange-400 text-sm transition-colors inline-flex items-center gap-1">
                  API Reference
                  <ExternalLink size={12} />
                </a>
              </li>
              <li>
                <a href="#" className="text-frost-dark-400 hover:text-frost-orange-400 text-sm transition-colors">
                  Support
                </a>
              </li>
            </ul>
          </div>
        </div>

        {/* Bottom bar */}
        <div className="mt-12 pt-8 border-t border-frost-dark-800">
          <div className="flex flex-col sm:flex-row justify-between items-center gap-4">
            <p className="text-frost-dark-500 text-xs">
              &copy; {new Date().getFullYear()} FrostGate Forge. All rights reserved.
            </p>
            <div className="flex items-center gap-6">
              <a href="#" className="text-frost-dark-500 hover:text-frost-dark-400 text-xs transition-colors">
                Privacy Policy
              </a>
              <a href="#" className="text-frost-dark-500 hover:text-frost-dark-400 text-xs transition-colors">
                Terms of Service
              </a>
            </div>
          </div>
        </div>
      </div>
    </footer>
  );
}
