const DANGEROUS_COMMANDS = {
  high: [
    // 文件系统操作
    '^(\\s*|.*\\|\\s*)dd if=/dev/zero\\b',
    '^(\\s*|.*\\|\\s*)mkfs.\\b',
    '^(\\s*|.*\\|\\s*)tee\\b',
    '^(\\s*|.*\\|\\s*)cat\\b.*(>.*|>>.*|<.*|<<.*)',
    '^(\\s*|.*\\|\\s*)cp\\b.*(--remove-destination.*|-f.*)',
    '^(\\s*|.*\\|\\s*)mv\\b.*(--remove-destination.*|-f.*)',
    '^(\\s*|.*\\|\\s*)find\\s+\\/.*-exec\\s+rm\\b',
    '^(\\s*|.*\\|\\s*)find\\s+\\/.*-delete\\b',
    '^(\\s*|.*\\|\\s*)cd\\s+\\.\\.\\/.*&&.*(rm|chmod|mv|cp)\\b',
    '^(\\s*|.*\\|\\s*)echo\\b.*\\s*[>|>>]\\s*\\/(etc|system|data)\\/',
    
    // 系统文件修改
    '^(\\s*|.*\\|\\s*)echo.*>/etc/passwd\\b',
    '^(\\s*|.*\\|\\s*)echo.*>/etc/shadow\\b',
    '^(\\s*|.*\\|\\s*)echo.*>/etc/fstab\\b',
    '^(\\s*|.*\\|\\s*)sed.*-i.*\\/etc\\/(passwd|shadow|fstab|hosts)\\b',
    '^(\\s*|.*\\|\\s*)awk.*-i inplace.*\\/etc\\/(passwd|shadow|fstab|hosts)\\b',
    
    // 权限提升
    '^(\\s*|.*\\|\\s*)su\\b',
    '^(\\s*|.*\\|\\s*)sudo\\b',
    '^(\\s*|.*\\|\\s*)adb root\\b',
    '^(\\s*|.*\\|\\s*)adb remount\\b',
    '^(\\s*|.*\\|\\s*)setenforce 0\\b',
    
    // 远程代码执行
    '^(\\s*|.*\\|\\s*)wget.*\\|.*(sh|bash|zsh|ksh)\\b',
    '^(\\s*|.*\\|\\s*)curl.*\\|.*(sh|bash|zsh|ksh)\\b',
    '^(\\s*|.*\\|\\s*)python.*<.*http\\b',
    '^(\\s*|.*\\|\\s*)perl.*<.*http\\b',
    
    // 系统控制
    '^(\\s*|.*\\|\\s*);reboot\\b',
    '^(\\s*|.*\\|\\s*);shutdown\\b',
    '^(\\s*|.*\\|\\s*);halt\\b',
    '^(\\s*|.*\\|\\s*);poweroff\\b',
    '^(\\s*|.*\\|\\s*)killall system_server\\b',
    
    // 权限设置
    '^(\\s*|.*\\|\\s*)chmod\\b.*(777|775|000|666)\\b',
    '^(\\s*|.*\\|\\s*)\\bchmod\\b.*000.*(\\/system\\/|\\/data\\/|\\/vendor\\/)',
    
    // 无限循环
    '^(\\s*|.*\\|\\s*)while true.*\\&\\b',
    '^(\\s*|.*\\|\\s*)for.*;;.*\\&\\b',
    '^(\\s*|.*\\|\\s*)while.*1.*\\&\\b',
    '^(\\s*|.*\\|\\s*)until.*0.*\\&\\b',
    
    // 资源耗尽
    '^(\\s*|.*\\|\\s*)yes\\b',
    '^(\\s*|.*\\|\\s*)yes.*\\&\\b',
    '^(\\s*|.*\\|\\s*)dd if=/dev/urandom of=/dev/sda\\b',
    '^(\\s*|.*\\|\\s*)cat /dev/urandom > /dev/null\\b',
    '^(\\s*|.*\\|\\s*)cat /dev/zero > /dev/null\\b'
  ],
  medium: [
    // 文件系统操作
    '^(\\s*|.*\\|\\s*)chmod(?!.*(77[0-7]|666|000))\\b',
    '^(\\s*|.*\\|\\s*)chown\\b',
    '^(\\s*|.*\\|\\s*)chgrp\\b',
    '^(\\s*|.*\\|\\s*)mount\\b',
    '^(\\s*|.*\\|\\s*)umount\\b',
    '^(\\s*|.*\\|\\s*)ln -s\\b',
    '^(\\s*|.*\\|\\s*)touch\\b',
    '^(\\s*|.*\\|\\s*)mkdir\\b',
    '^(\\s*|.*\\|\\s*)rmdir\\b',
    '^(\\s*|.*\\|\\s*)rm(?! -rf| -fr)\\b',
    
    // 用户管理
    '^(\\s*|.*\\|\\s*)useradd\\b',
    '^(\\s*|.*\\|\\s*)userdel\\b',
    '^(\\s*|.*\\|\\s*)groupadd\\b',
    '^(\\s*|.*\\|\\s*)groupdel\\b',
    '^(\\s*|.*\\|\\s*)passwd\\b',
    '^(\\s*|.*\\|\\s*)usermod\\b',
    
    // 临时目录操作
    '^(\\s*|.*\\|\\s*).*\\/tmp\\/.*\\b',
    '^(\\s*|.*\\|\\s*).*\\/var\\/tmp\\/.*\\b',
    '^(\\s*|.*\\|\\s*).*\\/dev\\/shm\\/.*\\b',
    
    // 网络命令
    '^(\\s*|.*\\|\\s*)wget(?!.*\\|.*(sh|bash|zsh|ksh))\\b',
    '^(\\s*|.*\\|\\s*)curl(?!.*\\|.*(sh|bash|zsh|ksh))\\b',
    '^(\\s*|.*\\|\\s*)telnet\\b',
    '^(\\s*|.*\\|\\s*)ftp\\b',
    '^(\\s*|.*\\|\\s*)nc\\b',
    '^(\\s*|.*\\|\\s*)ncat\\b',
    '^(\\s*|.*\\|\\s*)ssh\\b',
    '^(\\s*|.*\\|\\s*)scp\\b',
    '^(\\s*|.*\\|\\s*)rsync\\b',
    
    // 系统控制
    '^(\\s*|.*\\|\\s*)reboot\\b',
    '^(\\s*|.*\\|\\s*)shutdown\\b',
    '^(\\s*|.*\\|\\s*)halt\\b',
    '^(\\s*|.*\\|\\s*)poweroff\\b',
    '^(\\s*|.*\\|\\s*)reboot recovery\\b',
    '^(\\s*|.*\\|\\s*)reboot bootloader\\b',
    
    // 包管理
    '^(\\s*|.*\\|\\s*)pm uninstall\\b',
    '^(\\s*|.*\\|\\s*)am start\\b',
    '^(\\s*|.*\\|\\s*)adb install\\b',
    '^(\\s*|.*\\|\\s*)adb uninstall\\b'
  ],
  low: [
    // 系统信息
    '^(\\s*|.*\\|\\s*)ls\\b',
    '^(\\s*|.*\\|\\s*)df\\b',
    '^(\\s*|.*\\|\\s*)du\\b',
    '^(\\s*|.*\\|\\s*)ps\\b',
    '^(\\s*|.*\\|\\s*)top\\b',
    '^(\\s*|.*\\|\\s*)free\\b',
    '^(\\s*|.*\\|\\s*)uptime\\b',
    
    // 文件操作
    '^(\\s*|.*\\|\\s*)cp(?!.*--remove-destination.*|-f.*)\\b',
    '^(\\s*|.*\\|\\s*)mv(?!.*--remove-destination.*|-f.*)\\b',
    '^(\\s*|.*\\|\\s*)grep\\b',
    '^(\\s*|.*\\|\\s*)find\\b',
    '^(\\s*|.*\\|\\s*)sort\\b',
    '^(\\s*|.*\\|\\s*)uniq\\b',
    '^(\\s*|.*\\|\\s*)head\\b',
    '^(\\s*|.*\\|\\s*)tail\\b',
    '^(\\s*|.*\\|\\s*)less\\b',
    '^(\\s*|.*\\|\\s*)more\\b',
    '^(\\s*|.*\\|\\s*)rm -rf(?! /data/adb/\\*)\\b',
    '^(\\s*|.*\\|\\s*)rm -fr(?! /data/adb/\\*)\\b',
    
    // 网络命令
    '^(\\s*|.*\\|\\s*)traceroute\\b',
    '^(\\s*|.*\\|\\s*)tracepath\\b',
    '^(\\s*|.*\\|\\s*)netstat\\b',
    '^(\\s*|.*\\|\\s*)ifconfig\\b',
    '^(\\s*|.*\\|\\s*)ip\\b',
    
    // 时间管理
    '^(\\s*|.*\\|\\s*)date\\b',
    '^(\\s*|.*\\|\\s*)hwclock\\b',
    '^(\\s*|.*\\|\\s*)timedatectl\\b',
    '^(\\s*|.*\\|\\s*)sleep(?! [0-9]{4,})\\b',
    
    // 其他
    '^(\\s*|.*\\|\\s*)echo(?!.*>.*|.*>>.*)\\b',
    '^(\\s*|.*\\|\\s*)printf\\b',
    '^(\\s*|.*\\|\\s*)export\\b',
    '^(\\s*|.*\\|\\s*)source\\b',
    '^(\\s*|.*\\|\\s*)alias\\b',
    '^(\\s*|.*\\|\\s*)unalias\\b'
  ]
};

// 命令详细解释
const COMMAND_EXPLANATIONS = {
  'rm -rf': '递归删除文件和目录，可能导致不可恢复的数据丢失',
  'dd if=/dev/zero': '低级磁盘操作命令，可能覆盖重要数据',
  'mkfs.': '格式化文件系统命令，会删除指定磁盘上的所有数据',
  'cat(.*>.*|.*>>.*)': '查看、创建文件或覆盖写入某文件，尤其格外注意命令中带有“>>”或“>”',
  'chmod.*(777|775|000|666)': '赋予文件所有人过高或过低权限，存在安全风险或导致系统故障',
  'chmod.*000.*\\/system\\/|\\/data\\/|\\/vendor\\/': '恶意剥夺系统关键目录权限，导致系统无法正常运行',
  'wget.*\\|.*bash': '从网络下载并执行脚本，存在安全风险',
  'while true': '无限循环命令，可能导致系统资源耗尽',
  'su': '获取设备最高执行权限（root权限），运行时尤为注意检查脚本全部内容',
  'sed.*-i.*\\/etc\\/passwd': '直接修改系统用户文件，可能导致系统无法登录',
  'killall system_server': '终止Android系统核心服务，导致系统崩溃重启'
};

// 安全注释列表
const SAFETY_COMMENTS = {
  'rm -rf /data/adb/*': '删除Magisk模块缓存文件，属于正常清理操作',
  'reboot': '系统重启命令，在适当场景下是安全的',
  'shutdown -h now': '正常关闭系统，不会造成破坏',
  'chmod 755': '设置文件所有者具有读、写、执行权限，属于正常权限设置',
  'chmod 644': '设置文件所有者具有读、写权限，属于正常权限设置',
  'echo(?!.*>.*|.*>>.*)': '打印输出内容，正常操作',
  'cp(?!.*--remove-destination.*|.*-f.*)': '复制文件，无强制覆盖风险',
  'mv(?!.*--remove-destination.*|.*-f.*)': '移动文件，无强制覆盖风险'
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
  
// 危险命令列表，按风险级别分类
const DANGEROUS_COMMANDS = {
  high: [
    {
      regex: /^(?:\s*|.*\|\\s*)rm -rf(?! /data/adb/\*)\b/,
      display: 'rm -rf',
      explanation: '递归删除文件和目录，可能导致不可恢复的数据丢失'
    },
    {
      regex: /^(?:\s*|.*\|\\s*)dd if=\/dev\/zero\b/,
      display: 'dd if=/dev/zero',
      explanation: '低级磁盘操作命令，可能覆盖重要数据'
    },
    // 其他高风险命令...
  ],
  medium: [
    {
      regex: /^(?:\s*|.*\|\\s*)chmod(?!.*(77[0-7]|666|000))\b/,
      display: 'chmod',
      explanation: '修改文件权限命令，不当使用可能导致安全漏洞'
    },
    // 其他中风险命令...
  ],
  low: [
    {
      regex: /^(?:\s*|.*\|\\s*)ls\b/,
      display: 'ls',
      explanation: '列出目录内容，低风险操作'
    },
    // 其他低风险命令...
  ]
};

// 检查每一行是否包含危险命令
lines.forEach((line, lineNumber) => {
  // 跳过空行和注释
  if (!line.trim() || line.trim().startsWith('#')) return;
  
  // 检查高风险命令
  DANGEROUS_COMMANDS.high.forEach(item => {
    if (item.regex.test(line)) {
      issues.push({
        line: lineNumber + 1,
        command: item.display,
        lineContent: line,
        severity: 'high',
        explanation: item.explanation
      });
    }
  });
  
  // 类似地处理中风险和低风险命令
  DANGEROUS_COMMANDS.medium.forEach(item => {
    if (item.regex.test(line)) {
      issues.push({
        line: lineNumber + 1,
        command: item.display,
        lineContent: line,
        severity: 'medium',
        explanation: item.explanation
      });
    }
  });
  
  DANGEROUS_COMMANDS.low.forEach(item => {
    if (item.regex.test(line)) {
      issues.push({
        line: lineNumber + 1,
        command: item.display,
        lineContent: line,
        severity: 'low',
        explanation: item.explanation
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
