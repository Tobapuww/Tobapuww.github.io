// 危险命令列表，按风险级别分类
const DANGEROUS_COMMANDS = {
  high: [
    'rm -rf(?! /data/adb/\\*)', 'rm -fr(?! /data/adb/\\*)', 'dd if=/dev/zero', 'mkfs.', 
    'echo.*>/etc/passwd', 'echo.*>/etc/shadow', 'cat * > *',
    'wget.*\\|.*bash', 'curl.*\\|.*bash', // 远程下载并执行
    'chmod.*777', 'chmod.*775', // 过度权限设置
    'sed.*-i.*\\/etc\\/passwd', 'sed.*-i.*\\/etc\\/shadow', // 直接修改系统文件
    ';reboot', ';shutdown', ';halt', ';poweroff', // 作为命令链的一部分
    'while true.*\\&', 'for.*;;.*\\&' // 后台无限循环
  ],
  medium: [
    'chmod(?!.*77[0-7])', 'chown', 'chgrp', 'sudo', 'su -',
    'mount', 'umount', 'useradd', 'userdel', 'groupadd', 'groupdel', 'passwd',
    '/tmp/', '/var/tmp/', '/dev/shm/', 'cat * >> *', 'cp'
  ],
  low: [
    'reboot', 'shutdown', 'halt', 'poweroff', // 系统控制命令
    'wget', 'curl', 'lynx', 'telnet', 'ftp', // 网络命令
    'sleep 3600', 'sleep 86400', // 长时间休眠
    'while true', 'for.*;;', // 无限循环
    'rm -rf /data/adb/*', // Magisk模块清理
    'chmod.*666' // 宽松但常见的权限设置
  ]
};

// 命令详细解释
const COMMAND_EXPLANATIONS = {
  'rm -rf': '递归删除文件和目录，可能导致不可恢复的数据丢失',
  'dd if=/dev/zero': '低级磁盘操作命令，可能覆盖重要数据',
  'mkfs.': '格式化文件系统命令，会删除指定磁盘上的所有数据',
  'reboot': '重启系统命令，可能导致服务中断',
  'shutdown': '关闭系统命令，可能导致服务中断',
  'chmod': '修改文件权限命令，不当使用可能导致安全漏洞',
  'chmod.*777': '赋予文件所有人读、写、执行权限，存在安全风险',
  'wget': '从网络下载文件的命令，可能下载恶意代码',
  'curl': '数据传输命令，可能被用于执行远程代码',
  'wget.*\\|.*bash': '从网络下载并执行脚本，存在安全风险',
  'while true': '无限循环命令，可能导致系统资源耗尽',
  '/tmp/': '临时目录，常被用于存放临时文件，可能存在安全风险',
  'cp': '复制文件到某处，可能将系统文件强行覆盖或植入病毒，可能存在安全风险',
  'cat': '查看、创建文件或覆盖写入某文件 尤其格外注意命令中带有“>>”或“>”，可能存在安全风险',
  'su': '获取设备最高执行权限（root权限），运行时尤为注意检查脚本全部内容'
};

// 安全注释列表
const SAFETY_COMMENTS = {
  'rm -rf /data/adb/*': '删除Magisk模块缓存文件，属于正常清理操作',
  'reboot': '系统重启命令，在适当场景下是安全的',
  'shutdown -h now': '正常关闭系统，不会造成破坏',
  'chmod 755': '设置文件所有者具有读、写、执行权限，属于正常权限设置',
  'chmod 644': '设置文件所有者具有读、写权限，属于正常权限设置'
};

// 改进的分析函数
function analyzeShellScript(fileName, content) {
  const issues = [];
  
  // 按行分割内容
  const lines = content.split('\n');
  
  // 检查是否为加密脚本
  const isEncrypted = lines.some(line => 
    line.includes('ENC[') || 
    line.includes('openssl enc') || 
    line.includes('gpg --encrypt')
  );
  
  if (isEncrypted) {
    return {
      fileName,
      encrypted: true,
      issues: [],
      content
    };
  }
  
  // 检查每一行是否包含危险命令
  lines.forEach((line, lineNumber) => {
    // 跳过空行和注释
    if (!line.trim() || line.trim().startsWith('#')) return;
    
    // 检查高风险命令
    DANGEROUS_COMMANDS.high.forEach(command => {
      const regex = new RegExp(command);
      if (regex.test(line)) {
        issues.push({
          line: lineNumber + 1,
          command: command.replace(/\\\*|\(\?!.*\)/g, ''),
          lineContent: line,
          severity: 'high',
          explanation: COMMAND_EXPLANATIONS[command.replace(/\\\*|\(\?!.*\)/g, '')] || '高风险命令，可能导致系统损坏或数据丢失'
        });
      }
    });
    
    // 检查中风险命令
    DANGEROUS_COMMANDS.medium.forEach(command => {
      const regex = new RegExp(command);
      if (regex.test(line)) {
        issues.push({
          line: lineNumber + 1,
          command: command.replace(/\\\*|\(\?!.*\)/g, ''),
          lineContent: line,
          severity: 'medium',
          explanation: COMMAND_EXPLANATIONS[command.replace(/\\\*|\(\?!.*\)/g, '')] || '中风险命令，可能影响系统配置或安全'
        });
      }
    });
    
    // 检查低风险命令
    DANGEROUS_COMMANDS.low.forEach(command => {
      const regex = new RegExp(command);
      if (regex.test(line)) {
        issues.push({
          line: lineNumber + 1,
          command: command.replace(/\\\*|\(\?!.*\)/g, ''),
          lineContent: line,
          severity: 'low',
          explanation: COMMAND_EXPLANATIONS[command.replace(/\\\*|\(\?!.*\)/g, '')] || '低风险命令，可能影响系统性能或资源使用'
        });
      }
    });
  });
  
  return {
    fileName,
    encrypted: false,
    issues,
    content
  };
}

// 显示文件详情改进
function showFileDetails(result) {
  modalTitle.textContent = result.fileName;
  
  if (result.encrypted) {
    modalContent.innerHTML = `
      <div class="text-center py-8">
        <div class="w-16 h-16 rounded-full bg-warning/10 flex items-center justify-center mx-auto mb-4">
          <i class="fa fa-lock text-warning text-2xl"></i>
        </div>
        <h4 class="font-semibold text-gray-800">加密脚本</h4>
        <p class="text-gray-500 mt-2">此脚本已加密，无法分析其内容。⚠️除非你非常信任脚本来源，否则强烈不建议执行该脚本！</p>
      </div>
    `;
  } else if (result.error) {
    modalContent.innerHTML = `
      <p class="text-danger">${result.error}</p>
    `;
  } else {
    if (result.issues.length === 0) {
      modalContent.innerHTML = `
        <div class="text-center py-8">
          <div class="w-16 h-16 rounded-full bg-success/10 flex items-center justify-center mx-auto mb-4">
            <i class="fa fa-check text-success text-2xl"></i>
          </div>
          <h4 class="font-semibold text-gray-800">文件安全</h4>
          <p class="text-gray-500 mt-2">未检测到任何危险命令</p>
        </div>
      `;
    } else {
      let issuesHTML = '';
      
      result.issues.forEach(issue => {
        const severityClass = issue.severity === 'high' ? 'bg-danger/10 text-danger' : 
                              issue.severity === 'medium' ? 'bg-warning/10 text-warning' : 'bg-info/10 text-info';
        const severityText = issue.severity === 'high' ? '高风险' : 
                              issue.severity === 'medium' ? '中风险' : '低风险';
        
        // 检查是否有安全注释
        const safetyComment = Object.keys(SAFETY_COMMENTS).find(key => 
          new RegExp(key).test(issue.lineContent)
        );
        
        issuesHTML += `
          <div class="mb-4 border border-gray-200 rounded-lg overflow-hidden">
            <div class="p-3 ${severityClass}">
              <div class="flex justify-between items-center">
                <span class="font-medium">${severityText}</span>
                <span class="text-xs">第 ${issue.line} 行</span>
              </div>
            </div>
            <div class="p-4">
              <p class="text-sm text-gray-700 mb-2">
                包含危险命令: <code class="bg-gray-100 px-1 py-0.5 rounded text-xs">${issue.command}</code>
              </p>
              <p class="text-xs text-gray-500 mb-3">
                <i class="fa fa-info-circle mr-1"></i>
                ${issue.explanation}
              </p>
              <pre class="bg-gray-50 p-3 rounded text-xs overflow-x-auto">${issue.lineContent}</pre>
              ${safetyComment ? `<div class="mt-3 p-2 bg-primary/5 rounded text-xs text-primary">注释: ${SAFETY_COMMENTS[safetyComment]}</div>` : ''}
            </div>
          </div>
        `;
      });
      
      modalContent.innerHTML = `
        <div class="mb-6">
          <h5 class="font-semibold text-gray-800 mb-3">检测到的问题</h5>
          ${issuesHTML}
        </div>
        <div>
          <h5 class="font-semibold text-gray-800 mb-3">文件内容</h5>
          <pre class="bg-gray-800 text-white p-4 rounded-lg overflow-x-auto text-xs" style="max-height: 400px;">${result.content}</pre>
        </div>
      `;
    }
  }
  
  modal.classList.remove('hidden');
}    
