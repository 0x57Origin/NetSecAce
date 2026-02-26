class Quiz {
  constructor(moduleId, containerId, questions, isFinal = false) {
    this.moduleId = moduleId;
    this.container = document.getElementById(containerId);
    this.questions = this.shuffle([...questions]);
    this.isFinal = isFinal;
    this.current = 0;
    this.score = 0;
    this.answered = [];
    this.startTime = null;
    this.timerInterval = null;
    this.timeLimit = isFinal ? 45 * 60 : null; // 45 min for final exam
    this.timeElapsed = 0;
    this.render();
  }

  shuffle(arr) {
    for (let i = arr.length - 1; i > 0; i--) {
      const j = Math.floor(Math.random() * (i + 1));
      [arr[i], arr[j]] = [arr[j], arr[i]];
    }
    return arr;
  }

  render() {
    this.container.innerHTML = `
      <div id="quiz-start" class="text-center py-10">
        <div class="text-6xl mb-4">${this.isFinal ? '🏆' : '📝'}</div>
        <h2 class="text-2xl font-bold text-white mb-2">${this.isFinal ? 'Beginner Final Exam' : 'Module Quiz'}</h2>
        <p class="text-slate-400 mb-2">${this.questions.length} Questions${this.isFinal ? ' • 45 Minute Time Limit' : ''}</p>
        <p class="text-slate-500 text-sm mb-8">You need <span class="text-cyan-400 font-semibold">70%</span> or higher to pass</p>
        <button onclick="quizInstance.start()" class="bg-cyan-500 hover:bg-cyan-400 text-slate-900 font-bold px-8 py-3 rounded-xl transition-all duration-200 text-lg">
          Start ${this.isFinal ? 'Final Exam' : 'Quiz'}
        </button>
      </div>
      <div id="quiz-question" class="hidden"></div>
      <div id="quiz-results" class="hidden"></div>
    `;
  }

  start() {
    this.startTime = Date.now();
    document.getElementById('quiz-start').classList.add('hidden');
    if (this.isFinal) this.startTimer();
    this.showQuestion();
  }

  startTimer() {
    const timerEl = document.getElementById('quiz-timer');
    if (!timerEl) return;
    this.timerInterval = setInterval(() => {
      this.timeElapsed++;
      const remaining = this.timeLimit - this.timeElapsed;
      if (remaining <= 0) {
        clearInterval(this.timerInterval);
        this.finishExam();
        return;
      }
      const m = Math.floor(remaining / 60).toString().padStart(2, '0');
      const s = (remaining % 60).toString().padStart(2, '0');
      timerEl.textContent = `${m}:${s}`;
      if (remaining <= 300) timerEl.classList.add('text-red-400');
    }, 1000);
  }

  showQuestion() {
    if (this.current >= this.questions.length) {
      this.finishExam();
      return;
    }
    const q = this.questions[this.current];
    const qEl = document.getElementById('quiz-question');
    qEl.classList.remove('hidden');

    const moduleTag = q.module ? `<span class="text-xs bg-slate-700 text-slate-400 px-2 py-0.5 rounded-full ml-2">${q.module}</span>` : '';

    qEl.innerHTML = `
      <div class="mb-6">
        <div class="flex items-center justify-between mb-4 flex-wrap gap-2">
          <div class="flex items-center gap-3">
            <span class="text-sm text-slate-500">Question ${this.current + 1} of ${this.questions.length}</span>
            ${moduleTag}
          </div>
          ${this.isFinal ? `<span id="quiz-timer" class="text-cyan-400 font-mono font-bold text-lg">45:00</span>` : ''}
        </div>
        <div class="w-full bg-slate-800 rounded-full h-1.5 mb-6">
          <div class="bg-cyan-500 h-1.5 rounded-full transition-all duration-500" style="width: ${((this.current) / this.questions.length) * 100}%"></div>
        </div>
        <p class="text-white text-lg font-medium leading-relaxed">${q.question}</p>
      </div>
      <div id="options" class="space-y-3"></div>
      <div id="feedback" class="hidden mt-6"></div>
      <div id="next-btn" class="hidden mt-6 text-right">
        <button onclick="quizInstance.next()" class="bg-cyan-500 hover:bg-cyan-400 text-slate-900 font-bold px-6 py-2.5 rounded-xl transition-all">
          ${this.current + 1 === this.questions.length ? (this.isFinal ? 'Finish Exam' : 'See Results') : 'Next Question →'}
        </button>
      </div>
    `;

    const optionsEl = document.getElementById('options');
    const letters = ['A', 'B', 'C', 'D'];
    q.options.forEach((opt, i) => {
      const btn = document.createElement('button');
      btn.className = 'w-full text-left flex items-start gap-3 p-4 rounded-xl border border-slate-700 bg-slate-800/50 hover:border-cyan-500/50 hover:bg-slate-800 transition-all duration-150 group';
      btn.innerHTML = `
        <span class="min-w-[28px] h-7 flex items-center justify-center rounded-lg bg-slate-700 text-slate-300 text-sm font-bold group-hover:bg-cyan-500/20 group-hover:text-cyan-400 transition-all">${letters[i]}</span>
        <span class="text-slate-300 text-sm leading-relaxed pt-0.5">${opt}</span>
      `;
      btn.onclick = () => this.selectAnswer(i, q.correct, q.explanation);
      optionsEl.appendChild(btn);
    });
  }

  selectAnswer(selected, correct, explanation) {
    // Disable all buttons
    const buttons = document.querySelectorAll('#options button');
    buttons.forEach(b => { b.onclick = null; b.style.cursor = 'default'; });

    const letters = ['A', 'B', 'C', 'D'];
    const isCorrect = selected === correct;
    if (isCorrect) this.score++;
    this.answered.push({ selected, correct, isCorrect });

    // Color buttons
    buttons.forEach((btn, i) => {
      const badge = btn.querySelector('span:first-child');
      const text = btn.querySelector('span:last-child');
      if (i === correct) {
        btn.className = btn.className.replace('border-slate-700 bg-slate-800/50', 'border-emerald-500/70 bg-emerald-500/10');
        badge.className = badge.className.replace('bg-slate-700 text-slate-300', 'bg-emerald-500 text-white');
        text.className = text.className.replace('text-slate-300', 'text-emerald-300');
      } else if (i === selected && !isCorrect) {
        btn.className = btn.className.replace('border-slate-700 bg-slate-800/50', 'border-red-500/70 bg-red-500/10');
        badge.className = badge.className.replace('bg-slate-700 text-slate-300', 'bg-red-500 text-white');
        text.className = text.className.replace('text-slate-300', 'text-red-300');
      } else {
        btn.className = btn.className.replace('hover:border-cyan-500/50 hover:bg-slate-800', '');
        text.className = text.className.replace('text-slate-300', 'text-slate-500');
      }
    });

    // Show feedback
    const feedbackEl = document.getElementById('feedback');
    feedbackEl.classList.remove('hidden');
    feedbackEl.innerHTML = `
      <div class="flex gap-3 p-4 rounded-xl ${isCorrect ? 'bg-emerald-500/10 border border-emerald-500/30' : 'bg-red-500/10 border border-red-500/30'}">
        <div class="text-2xl">${isCorrect ? '✅' : '❌'}</div>
        <div>
          <p class="font-semibold ${isCorrect ? 'text-emerald-400' : 'text-red-400'} mb-1">${isCorrect ? 'Correct!' : `Incorrect — the answer is ${letters[correct]}`}</p>
          <p class="text-slate-400 text-sm leading-relaxed">${explanation}</p>
        </div>
      </div>
    `;

    document.getElementById('next-btn').classList.remove('hidden');
  }

  next() {
    this.current++;
    this.showQuestion();
  }

  finishExam() {
    if (this.timerInterval) clearInterval(this.timerInterval);
    const timeTaken = Math.floor((Date.now() - this.startTime) / 1000);
    const m = Math.floor(timeTaken / 60);
    const s = timeTaken % 60;
    const percent = Math.round((this.score / this.questions.length) * 100);
    const passed = percent >= 70;

    document.getElementById('quiz-question').classList.add('hidden');
    const resultsEl = document.getElementById('quiz-results');
    resultsEl.classList.remove('hidden');

    // Save progress
    Progress.setModuleScore(this.moduleId, this.score, this.questions.length);

    const grade = percent >= 90 ? 'A' : percent >= 80 ? 'B' : percent >= 70 ? 'C' : percent >= 60 ? 'D' : 'F';
    const gradeColor = passed ? 'text-emerald-400' : 'text-red-400';
    const ringColor = passed ? '#10b981' : '#ef4444';

    resultsEl.innerHTML = `
      <div class="text-center py-8">
        <div class="text-5xl mb-4">${passed ? '🎉' : '📚'}</div>
        <h2 class="text-2xl font-bold text-white mb-1">${passed ? 'Passed!' : 'Keep Studying!'}</h2>
        <p class="text-slate-400 mb-8">${passed ? 'Great work! You have the fundamentals down.' : 'Review the lessons and try again — you can do it!'}</p>

        <div class="grid grid-cols-3 gap-4 max-w-md mx-auto mb-8">
          <div class="bg-slate-800 rounded-xl p-4">
            <div class="text-3xl font-bold ${gradeColor}">${grade}</div>
            <div class="text-slate-500 text-xs mt-1">Grade</div>
          </div>
          <div class="bg-slate-800 rounded-xl p-4">
            <div class="text-3xl font-bold text-white">${percent}%</div>
            <div class="text-slate-500 text-xs mt-1">Score</div>
          </div>
          <div class="bg-slate-800 rounded-xl p-4">
            <div class="text-3xl font-bold text-cyan-400">${this.score}/${this.questions.length}</div>
            <div class="text-slate-500 text-xs mt-1">Correct</div>
          </div>
        </div>

        <div class="bg-slate-800 rounded-xl p-4 max-w-md mx-auto mb-8 text-left">
          <h3 class="text-white font-semibold mb-3">Question Breakdown</h3>
          <div class="space-y-1 max-h-48 overflow-y-auto pr-1">
            ${this.answered.map((a, i) => `
              <div class="flex items-center gap-2 text-sm">
                <span>${a.isCorrect ? '✅' : '❌'}</span>
                <span class="${a.isCorrect ? 'text-slate-400' : 'text-red-400'}">Q${i + 1}</span>
                <span class="text-slate-500 truncate text-xs">${this.questions[i].question.substring(0, 55)}...</span>
              </div>
            `).join('')}
          </div>
        </div>

        <div class="flex gap-3 justify-center flex-wrap">
          <button onclick="location.reload()" class="bg-slate-700 hover:bg-slate-600 text-white font-semibold px-5 py-2.5 rounded-xl transition-all">
            Retry Quiz
          </button>
          ${!this.isFinal ? `<a href="index.html" class="bg-cyan-500 hover:bg-cyan-400 text-slate-900 font-bold px-5 py-2.5 rounded-xl transition-all">Back to Home</a>` : ''}
          ${passed && !this.isFinal ? this.getNextModuleBtn() : ''}
        </div>
      </div>
    `;
  }

  getNextModuleBtn() {
    const next = { module1: 'module2', module2: 'module3', module3: 'module4', module4: 'module5' };
    const labels = { module2: 'Module 2', module3: 'Module 3', module4: 'Module 4', module5: 'Final Exam' };
    const nextId = next[this.moduleId];
    if (!nextId) return '';
    return `<a href="${nextId}.html" class="bg-emerald-500 hover:bg-emerald-400 text-slate-900 font-bold px-5 py-2.5 rounded-xl transition-all">Next: ${labels[nextId]} →</a>`;
  }
}

let quizInstance = null;

function initQuiz(moduleId, containerId, isFinal = false) {
  const questions = isFinal ? FINAL_EXAM_QUESTIONS : QUESTIONS[moduleId];
  quizInstance = new Quiz(moduleId, containerId, questions, isFinal);
}
