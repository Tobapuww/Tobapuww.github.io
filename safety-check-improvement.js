// 危险命令列表，按风险级别分类
const DANGEROUS_COMMANDS = {
high: [
  // 文件系统操作
  'rm -rf(?! /data/adb/\\*)', 'rm -fr(?! /data/adb/\\*)', 'dd if=/dev/zero', 'mkfs.', 'tee',
  'cat(.*>.*|.*>>.*|.*<.*|.*<<.*)', // 带重定向的cat命令
  'cp(.*--remove-destination.*|.*-f.*)', // 强制复制命令
  'mv(.*--remove-destination.*|.*-f.*)', // 强制移动命令
  'find\\s+\\/.*-exec\\s+rm',
  'find\\s+\\/.*-delete',
  'cd\\s+\\.\\.\\/.*&&.*(rm|chmod|mv|cp)', // 切换目录后执行危险命令
  'echo\\s+.*\\s*[>|>>]\\s*\\/(etc|system|data)\\/', // 写入系统目录
  
  // 系统文件修改
  'echo.*>/etc/passwd', 'echo.*>/etc/shadow', 'echo.*>/etc/fstab',
  'sed.*-i.*\\/etc\\/(passwd|shadow|fstab|hosts)',
  'awk.*-i inplace.*\\/etc\\/(passwd|shadow|fstab|hosts)',
  
  // 权限提升
  'su', 'sudo', 'adb root', 'adb remount', 'setenforce 0',
  
  // 远程代码执行
  'wget.*\\|.*(sh|bash|zsh|ksh)', 'curl.*\\|.*(sh|bash|zsh|ksh)',
  'python.*<.*http', 'perl.*<.*http',
  
  // 系统控制
  ';reboot', ';shutdown', ';halt', ';poweroff', 'killall system_server',
  
  // 权限设置
  'chmod.*(777|775|000|666)', // 高风险权限值
  '\\bchmod\\b.*000.*(\\/system\\/|\\/data\\/|\\/vendor\\/)', // 系统目录权限剥夺
  
  // 无限循环
  'while true.*\\&', 'for.*;;.*\\&', 'while.*1.*\\&', 'until.*0.*\\&',
  
  // 资源耗尽
  'yes', 'yes.*\\&', 'dd if=/dev/urandom of=/dev/sda',
  'cat /dev/urandom > /dev/null', 'cat /dev/zero > /dev/null'
],
  medium: [
    // 文件系统操作
    'chmod(?!.*(77[0-7]|666|000))', 'chown', 'chgrp', 'mount', 'umount',
    'ln -s', 'touch', 'mkdir', 'rmdir', 'rm(?! -rf| -fr)',
    
    // 用户管理
    'useradd', 'userdel', 'groupadd', 'groupdel', 'passwd', 'usermod',
    
    // 临时目录操作
    '.*\\/tmp\\/.*', '.*\\/var\\/tmp\\/.*', '.*\\/dev\\/shm\\/.*',
    
    // 网络命令
    'wget(?!.*\\|.*(sh|bash|zsh|ksh))', 'curl(?!.*\\|.*(sh|bash|zsh|ksh))',
    'telnet', 'ftp', 'nc', 'ncat', 'ssh', 'scp', 'rsync',
    
    // 系统控制
    'reboot', 'shutdown', 'halt', 'poweroff', 'reboot recovery', 'reboot bootloader',
    
    // 包管理
    'pm uninstall', 'am start', 'adb install', 'adb uninstall'
  ],
  low: [
    // 系统信息
    'ls', 'df', 'du', 'ps', 'top', 'free', 'uptime',
    
    // 文件操作
    'cp(?!.*--remove-destination.*|.*-f.*)', 'mv(?!.*--remove-destination.*|.*-f.*)',
    'grep', 'find', 'sort', 'uniq', 'head', 'tail', 'less', 'more',
    
    // 网络命令
    'ping', 'ping6', 'traceroute', 'tracepath', 'netstat', 'ifconfig', 'ip',
    
    // 时间管理
    'date', 'hwclock', 'timedatectl', 'sleep(?! [0-9]{4,})',
    
    // 其他
    'echo(?!.*>.*|.*>>.*)', 'printf', 'export', 'source', 'alias', 'unalias',
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
  'cat(?!.*>.*|.*>>.*)': '查看文件内容，正常操作',
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
