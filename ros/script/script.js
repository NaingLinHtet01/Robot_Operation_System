document.addEventListener('DOMContentLoaded', function() {
    const uploadBtn = document.getElementById('upload-btn');
    const executeBtn = document.getElementById('execute-btn');
    const excelFileInput = document.getElementById('excelFile');
    const ipInput = document.getElementById('ip');
    const usernameInput = document.getElementById('username');
    const passwordInput = document.getElementById('password');
    const targetOsType = document.getElementById('target-os-type');
    const cmdContainer = document.querySelector('.cmd-container');
    const chkCmdTab = document.querySelector('.chk-cmd-tab');
    const cmdResultTab = document.querySelector('.cmd-result-tab');
    const loadingModal = document.getElementById('loading-modal');
    const loadingText = document.getElementById('loading-text');
    const connectionInputs = [ipInput, usernameInput, passwordInput, excelFileInput];
    const server = 'http://192.168.250.6:5000';
    let requiresVerification = false;
    let verificationCode = '';
    const verificationModal = document.getElementById('verification-modal');
    const verificationInput = document.getElementById('verification-code');
    const verifyBtn = document.getElementById('verify-btn');
    const cancelBtn = document.getElementById('cancel-verify');
    const approvalBtn = document.getElementById('approval-btn');

    let commands = [];
    let validationResults = [];
    executeBtn.disabled = true;
    
    function resetUI() {
    chkCmdTab.style.display = 'none';
    cmdResultTab.style.display = 'none';
    executeBtn.disabled = true;
    commands = [];
    validationResults = [];
    cmdContainer.innerHTML = `
        <div class="cmd-header">
            <span>ID</span>
            <span>Commands</span>
            <span>Comment</span>
            <span>Valid</span>
        </div>
    `;
    document.querySelector('.results').innerHTML = '';
    }

    // Loading
    function showLoading(message) {
        loadingText.textContent = message;
        loadingModal.style.display = 'flex';
    }
    function hideLoading() {
        loadingModal.style.display = 'none';
    }
    

    uploadBtn.addEventListener('click', function() {
        const file = excelFileInput.files[0];
        if (!file) {
            alert('Please select an Excel file');
            return;
        }
        
        const ip = ipInput.value.trim();
        const username = usernameInput.value.trim();
        const password = passwordInput.value.trim();
        
        if (!ip || !username || !password) {
            alert('Please fill in all connection details');
            return;
        }
        
        showLoading('Validating commands...');
        
        const reader = new FileReader();
        reader.onload = function(e) {
            const data = new Uint8Array(e.target.result);
            const workbook = XLSX.read(data, { type: 'array' });
            
            // Assuming first sheet contains the commands
            const firstSheet = workbook.Sheets[workbook.SheetNames[0]];
            const jsonData = XLSX.utils.sheet_to_json(firstSheet);
            
            commands = jsonData.map((item, index) => ({
                id: index + 1,
                description: item.Description || 'No description',
                command: item.Command
            }));
            
            
            validateCommands(ip, username, password, commands);
        };
        reader.readAsArrayBuffer(file);
    });

    connectionInputs.forEach(input => {
    input.addEventListener('change', resetUI);
    });

    
    executeBtn.addEventListener('click', function() {
        const ip = ipInput.value.trim();
        const username = usernameInput.value.trim();
        const password = passwordInput.value.trim();
        
        if (!ip || !username || !password) {
            alert('Please fill in all connection details');
            return;
        }
        
        showLoading('Executing commands...');
        
       
        const validCommands = validationResults.filter(cmd => cmd.valid).map(cmd => ({
            id: cmd.id,
            command: cmd.command
        }));
        
        executeCommands(ip, username, password, validCommands);
    });
    
    
    function validateCommands(ip, username, password, commands) {
    fetch(`${server}/validate_commands`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({
            ip: ip,
            username: username,
            password: password,
            commands: commands
        })
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            targetOsType.textContent = data.os_type;
            validationResults = data.results;
            requiresVerification = data.requires_verification;
            verificationCode = data.verification_code; // For testing only
            
            displayValidationResults(data.results, data.os_type, data.connection_type);
            
            if (requiresVerification) {
                // Show verification modal
                verificationModal.style.display = 'flex';
                executeBtn.disabled = true;
            } else {
                executeBtn.disabled = !data.all_valid;
            }
            
            // Show command validation tab
            chkCmdTab.style.display = 'block';
            chkCmdTab.scrollIntoView({ behavior: 'smooth' });
        } else {
            alert('Error validating commands: ' + data.error);
        }
        hideLoading();
    })
    .catch(error => {
        console.error('Error:', error);
        alert('Error validating commands');
        hideLoading();
    });
}

    // Add verification functionality
    verifyBtn.addEventListener('click', function() {
        const code = verificationInput.value.trim();
        const ip = ipInput.value.trim();
        
        if (!code) {
            alert('Please enter the verification code');
            return;
        }
        
        showLoading('Verifying code...');
        
        fetch(`${server}/verify_code`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                ip: ip,
                code: code
            })
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                if (data.verified) {
                    // Code is correct, enable execute button
                    verificationModal.style.display = 'none';
                    approvalBtn.disabled = true;
                    approvalBtn.classList.add('hide');
                    verificationInput.value = '';
                    executeBtn.disabled = false;
                    alert('Verification successful! You can now execute commands.');
                } else {
                    alert('Invalid verification code. Please try again.');
                }
            } else {
                alert('Error verifying code: ' + data.error);
            }
            hideLoading();
        })
        .catch(error => {
            console.error('Error:', error);
            alert('Error verifying code');
            hideLoading();
        });
    });
    
    cancelBtn.addEventListener('click', function() {
        verificationModal.style.display = 'none';
        verificationInput.value = '';
        approvalBtn.disabled = false;
        approvalBtn.classList.remove('hide');

    });
    
    approvalBtn.addEventListener('click', function(){
        verificationModal.style.display = 'flex';
        approvalBtn.disabled = true;
        approvalBtn.classList.add('hide');
    })


    // Update the displayValidationResults function to highlight sensitive commands
    function displayValidationResults(results, osType, connectionType) {
        targetOsType.textContent = `${osType} (${connectionType})`;
    
        cmdContainer.innerHTML = `
            <div class="cmd-header">
                <span>ID</span>
                <span>Commands</span>
                <span>Comment</span>
                <span>Valid</span>
            </div>
        `;
        
        results.forEach(result => {
            const cmdItem = document.createElement('div');
            cmdItem.className = 'cmd-item';
            
            // Add sensitive class if command is sensitive
            if (result.sensitive) {
                cmdItem.classList.add('sensitive-cmd');
            }
            
            let commentContent = result.valid ? 'Command Valid!' : 'Invalid Commands!';
            let isWarning = false;
            
            if (result.suggestions && result.suggestions.length > 0) {
                if (result.valid) {
                    isWarning = true;
                    commentContent += `<div class="warning">${result.suggestions.join(', ')}</div>`;
                } else {
                    commentContent += `<div class="suggestions">${result.suggestions.join(', ')}</div>`;
                }
            }
            
            // Add note for sensitive commands
            if (result.sensitive) {
                commentContent += `<div class="sensitive-note">Sensitive command - verification required</div>`;
            }
            
            if (!result.valid) {
                cmdItem.classList.add('argument-error');
            } else if (isWarning) {
                cmdItem.classList.add('argument-warning');
            }
            
            cmdItem.innerHTML = `
                <span class="no">${result.id}</span>
                <div class="cmd_des">
                    <span class="description">${result.description}</span>
                    <span class="cmds">${result.command}</span>
                </div>
                <span class="comment">
                    ${commentContent}
                </span>
                <span class="valid">
                    <img src="./assets/imgs/${result.valid ? (isWarning ? 'warning' : 'valid') : 'invalid'}.png" 
                         alt="${result.valid ? (isWarning ? 'warning' : 'valid') : 'invalid'}" class="icon">
                </span>
            `;
            
            cmdContainer.appendChild(cmdItem);
        });
    }

    
   
    function executeCommands(ip, username, password, commands) {
        fetch(`${server}/execute_commands`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                ip: ip,
                username: username,
                password: password,
                commands: commands
            })
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                displayExecutionResults(data.results, data.os_type, data.connection_type);
                
               
                cmdResultTab.style.display = 'block';
                
                
                cmdResultTab.scrollIntoView({ behavior: 'smooth' });
            } else {
                alert('Error executing commands: ' + data.error);
            }
            hideLoading();
        })
        .catch(error => {
            console.error('Error:', error);
            alert('Error executing commands');
            hideLoading();
        });
    }
    
    
    function displayValidationResults(results, osType, connectionType) {

    targetOsType.textContent = `${osType} (${connectionType})`;


    cmdContainer.innerHTML = `
        <div class="cmd-header">
            <span>ID</span>
            <span>Commands</span>
            <span>Comment</span>
            <span>Valid</span>
        </div>
    `;
    
    results.forEach(result => {
        const cmdItem = document.createElement('div');
        cmdItem.className = 'cmd-item';
        
        let commentContent = result.valid ? 'Command Valid!' : 'Invalid Commands!';
        let isWarning = false;
        
        if (result.suggestions && result.suggestions.length > 0) {
            if (result.valid) {
                
                isWarning = true;
                commentContent += `<div class="warning">${result.suggestions.join(', ')}</div>`;
            } else {
               
                commentContent += `<div class="suggestions">${result.suggestions.join(', ')}</div>`;
            }
        }
        
       
        if (!result.valid) {
            cmdItem.classList.add('argument-error');
        } else if (isWarning) {
            cmdItem.classList.add('argument-warning');
        }
        
        cmdItem.innerHTML = `
            <span class="no">${result.id}</span>
            <div class="cmd_des">
                <span class="description">${result.description}</span>
                <span class="cmds">${result.command}</span>
            </div>
            <span class="comment">
                ${commentContent}
            </span>
            <span class="valid">
                <img src="./assets/imgs/${result.valid ? (isWarning ? 'warning' : 'valid') : 'invalid'}.png" 
                     alt="${result.valid ? (isWarning ? 'warning' : 'valid') : 'invalid'}" class="icon">
            </span>
        `;
        
        cmdContainer.appendChild(cmdItem);
    });
}
    
    
    function displayExecutionResults(results, osType, connectionType) {
        const resultContainer = document.querySelector('.results');
        resultContainer.innerHTML = '';
        
        
        const silentCommands = ['cp', 'mv', 'rm', 'chmod', 'mkdir', 'touch'];
        
        results.forEach(result => {
            const resultItem = document.createElement('div');
            resultItem.className = 'result-item';
            
            
            const isSilentCommand = silentCommands.some(cmd => 
                result.command.trim().startsWith(cmd)
            );
            
            let displayOutput = result.output;
            if (isSilentCommand && !result.output) {
                displayOutput = 'Executed successfully';
            } else if (result.output.includes('No such file or directory') || 
                      result.output.includes('command not found') || 
                      result.output.includes('Permission denied')) {
                displayOutput = `Error: ${result.output}`;
            }
            
            resultItem.innerHTML = `
                <div class="result-top">
                    <span class="result-no">${result.id}</span>
                    <span class="result-command">${result.command}</span>
                </div>
                <pre class="result-return">${displayOutput}</pre>
            `;
            
            resultContainer.appendChild(resultItem);
        });
    }

    // Light Dark

    
            const toggle = document.getElementById('theme-toggle');
            const resetButton = document.getElementById('reset-button');
            const savedTheme = localStorage.getItem('theme');
            
            if (savedTheme) {
                document.documentElement.setAttribute('data-theme', savedTheme);
                toggle.checked = savedTheme === 'dark';
            } else {
                
                const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
                if (prefersDark) {
                    document.documentElement.setAttribute('data-theme', 'dark');
                    toggle.checked = true;
                }
            }
            
            
            toggle.addEventListener('change', () => {
                if (toggle.checked) {
                    document.documentElement.setAttribute('data-theme', 'dark');
                    localStorage.setItem('theme', 'dark');
                } else {
                    document.documentElement.setAttribute('data-theme', 'light');
                    localStorage.setItem('theme', 'light');
                }
            });
            
            
            resetButton.addEventListener('click', () => {
                localStorage.removeItem('theme');
                const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
                
                if (prefersDark) {
                    document.documentElement.setAttribute('data-theme', 'dark');
                    toggle.checked = true;
                } else {
                    document.documentElement.setAttribute('data-theme', 'light');
                    toggle.checked = false;
                }
            });



});

function downloadResults() {
const ip = document.getElementById('ip').value.trim();
const osType = document.getElementById('target-os-type').textContent;
const filename = `${ip}_${osType}_cmd_results.txt`.replace(/[^a-zA-Z0-9._-]/g, '_');
const resultItems = document.querySelectorAll('.result-item');

let textContent = `Command Execution Results\n`;
textContent += `IP: ${ip}\n`;
textContent += `OS Type: ${osType}\n`;
textContent += `Date: ${new Date().toLocaleString()}\n`;
textContent += '='.repeat(50) + '\n\n';

resultItems.forEach(item => {
    const command = item.querySelector('.result-command').textContent;
    const output = item.querySelector('.result-return').textContent;
    
    textContent += `Command ${item.querySelector('.result-no').textContent}:\n`;
    textContent += `Command: ${command}\n`;
    textContent += `Output:\n${output}\n`;
    textContent += '-'.repeat(30) + '\n\n';
});


const blob = new Blob([textContent], { type: 'text/plain' });
const url = URL.createObjectURL(blob);
const a = document.createElement('a');
a.href = url;
a.download = filename;
document.body.appendChild(a);
a.click();
document.body.removeChild(a);
URL.revokeObjectURL(url);
}

