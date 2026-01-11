const fs = require('fs').promises;
const path = require('path');
const { glob } = require('glob');

/**
 * Parse all data from the pipeline output directories
 */
async function parseAllData(baseDir) {
  console.log('Parsing data from:', baseDir);
  
  const data = {
    pipelineRuns: [],
    validations: [],
    patchGeneration: [],
    reproductions: [],
    feedbackLoop: null,
    cves: [],
    models: []
  };

  try {
    // Parse pipeline run results
    data.pipelineRuns = await parsePipelineRuns(baseDir);
    
    // Parse validation results
    data.validations = await parseValidations(baseDir);
    
    // Parse patch generation results
    data.patchGeneration = await parsePatchGeneration(baseDir);
    
    // Parse reproduction results
    data.reproductions = await parseReproductions(baseDir);
    
    // Parse feedback loop results
    data.feedbackLoop = await parseFeedbackLoop(baseDir);
    
    // Extract unique CVEs and models
    data.cves = [...new Set(data.validations.map(v => v.cve_id))];
    data.models = [...new Set(data.validations.map(v => v.model_name))];
    
    console.log(`Parsed: ${data.validations.length} validations, ${data.cves.length} CVEs, ${data.models.length} models`);
  } catch (error) {
    console.error('Error parsing data:', error);
  }

  return data;
}

/**
 * Parse pipeline run files
 */
async function parsePipelineRuns(baseDir) {
  const runs = [];
  const resultsDir = path.join(baseDir, 'results');
  
  try {
    const files = await glob('pipeline_run_*.json', { cwd: resultsDir });
    
    for (const file of files) {
      const filePath = path.join(resultsDir, file);
      const content = await fs.readFile(filePath, 'utf-8');
      const data = JSON.parse(content);
      runs.push(data);
    }
  } catch (error) {
    console.error('Error parsing pipeline runs:', error);
  }
  
  return runs.sort((a, b) => new Date(b.start_time) - new Date(a.start_time));
}

/**
 * Parse validation summary and individual validation files
 */
async function parseValidations(baseDir) {
  const validations = [];
  const validationDir = path.join(baseDir, 'validation_results');
  
  try {
    // First try to parse the summary file
    const summaryFiles = await glob('validation_summary_*.json', { cwd: validationDir });
    
    if (summaryFiles.length > 0) {
      // Get the most recent summary
      const summaryPath = path.join(validationDir, summaryFiles.sort().pop());
      const content = await fs.readFile(summaryPath, 'utf-8');
      const summary = JSON.parse(content);
      
      // Extract validations from by_cve structure
      if (summary.by_cve) {
        for (const [cveId, cveValidations] of Object.entries(summary.by_cve)) {
          for (const v of cveValidations) {
            validations.push({
              ...v,
              cve_id: cveId
            });
          }
        }
      }
    }
    
    // Also parse individual validation files
    const individualFiles = await glob('*/*_validation.json', { cwd: validationDir });
    
    for (const file of individualFiles) {
      const filePath = path.join(validationDir, file);
      try {
        const content = await fs.readFile(filePath, 'utf-8');
        const data = JSON.parse(content);
        
        // Check if this validation is already in the list
        const exists = validations.some(v => 
          v.cve_id === data.cve_id && 
          v.model_name === data.model_name &&
          v.timestamp === data.timestamp
        );
        
        if (!exists) {
          validations.push(data);
        }
      } catch (e) {
        console.error(`Error parsing ${file}:`, e.message);
      }
    }
  } catch (error) {
    console.error('Error parsing validations:', error);
  }
  
  return validations;
}

/**
 * Parse patch generation results
 */
async function parsePatchGeneration(baseDir) {
  const patches = [];
  const patchDir = path.join(baseDir, 'patches');
  
  try {
    // Parse pipeline summary
    const summaryPath = path.join(patchDir, 'pipeline_summary.json');
    try {
      const content = await fs.readFile(summaryPath, 'utf-8');
      const summary = JSON.parse(content);
      
      if (summary.results) {
        patches.push(...summary.results);
      }
    } catch (e) {
      // Summary file may not exist
    }
    
    // Parse individual response.json files for more details
    const responseFiles = await glob('*/*/response.json', { cwd: patchDir });
    
    for (const file of responseFiles) {
      const filePath = path.join(patchDir, file);
      try {
        const content = await fs.readFile(filePath, 'utf-8');
        const data = JSON.parse(content);
        
        // Add path info
        const pathParts = file.split('/');
        data.cve_id = pathParts[0];
        data.model_folder = pathParts[1];
        
        // Check if not already in patches
        const exists = patches.some(p => 
          p.cve_id === data.cve_id && 
          p.model === data.model
        );
        
        if (!exists) {
          patches.push(data);
        }
      } catch (e) {
        console.error(`Error parsing ${file}:`, e.message);
      }
    }
  } catch (error) {
    console.error('Error parsing patch generation:', error);
  }
  
  return patches;
}

/**
 * Parse vulnerability reproduction results
 */
async function parseReproductions(baseDir) {
  const reproductions = [];
  const resultsDir = path.join(baseDir, 'results');
  
  try {
    const resultsPath = path.join(resultsDir, 'results.json');
    const content = await fs.readFile(resultsPath, 'utf-8');
    const data = JSON.parse(content);
    
    if (data.results) {
      reproductions.push(...data.results);
    }
  } catch (error) {
    console.error('Error parsing reproductions:', error);
  }
  
  return reproductions;
}

/**
 * Parse feedback loop results
 */
async function parseFeedbackLoop(baseDir) {
  const resultsDir = path.join(baseDir, 'results');
  
  try {
    const files = await glob('feedback_loop_results_*.json', { cwd: resultsDir });
    
    if (files.length > 0) {
      const filePath = path.join(resultsDir, files.sort().pop());
      const content = await fs.readFile(filePath, 'utf-8');
      return JSON.parse(content);
    }
  } catch (error) {
    console.error('Error parsing feedback loop:', error);
  }
  
  return null;
}

module.exports = {
  parseAllData,
  parsePipelineRuns,
  parseValidations,
  parsePatchGeneration,
  parseReproductions,
  parseFeedbackLoop
};
