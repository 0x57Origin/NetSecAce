const Progress = {
  KEY: 'netsecace_progress',

  get() {
    try {
      return JSON.parse(localStorage.getItem(this.KEY)) || {};
    } catch {
      return {};
    }
  },

  save(data) {
    localStorage.setItem(this.KEY, JSON.stringify(data));
  },

  setModuleScore(moduleId, score, total) {
    const data = this.get();
    if (!data[moduleId]) data[moduleId] = {};
    data[moduleId].score = score;
    data[moduleId].total = total;
    data[moduleId].passed = (score / total) >= 0.7;
    data[moduleId].completedAt = new Date().toISOString();
    this.save(data);
  },

  getModuleData(moduleId) {
    return this.get()[moduleId] || null;
  },

  isModuleCompleted(moduleId) {
    const data = this.getModuleData(moduleId);
    return data ? data.passed : false;
  },

  getOverallProgress() {
    const data = this.get();
    const modules = ['module1', 'module2', 'module3', 'module4', 'module5'];
    const completed = modules.filter(m => this.isModuleCompleted(m)).length;
    return { completed, total: modules.length, percent: Math.round((completed / modules.length) * 100) };
  },

  reset() {
    localStorage.removeItem(this.KEY);
  }
};
