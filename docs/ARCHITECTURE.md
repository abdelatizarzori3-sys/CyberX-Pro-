# CyberX Pro — المخطط الهندسي والتنفيذي

> **الإصدار:** 1.0  
> **المبدأ الحاكم:** لا يُنفّذ أي تقييم أمني إلا على أصل ضمن نطاق تفويض موثّق وساري. يظل الذكاء الاصطناعي استشارياً، ولا يقرر التفويض أو يشغّل الفحوص.

## المخطط المعماري

```mermaid
flowchart TB
    subgraph Clients[واجهات المستخدم]
        Mobile[تطبيق Flutter]
        Web[تطبيق الويب Next.js]
        Admin[لوحة الإدارة]
    end

    subgraph Edge[طبقة الوصول والهوية]
        Gateway[API Gateway<br/>/api/v1 · التحقق من المدخلات · تحديد المعدل]
        Identity[الهوية وإدارة الوصول<br/>المصادقة · MFA · RBAC · الجلسات]
    end

    subgraph Core[النواة المركزية — FastAPI]
        Org[المؤسسات والمشاريع<br/>عزل متعدد المستأجرين]
        Assets[الأصول والتصنيف]
        Authz[التفويض والتحقق من النطاق<br/>الملكية · الصلاحية الزمنية · الموافقات · الإلغاء]
        Orchestrator[منظّم المهام<br/>الجدولة · الحدود · الإلغاء · تتبع الحالة]
        Vuln[إدارة الثغرات والمعالجة]
        Defense[الدفاع والحوادث والاستجابة]
        Forensics[القضايا والأدلة الرقمية<br/>Hash · سلسلة الحيازة]
        Threat[استخبارات التهديدات]
        Reports[التقارير والتصدير]
        AI[مساعد AI استشاري<br/>شرح وتحليل وتوصيات بمصادر وثقة]
        Billing[الاشتراكات والفوترة]
        Audit[سجل التدقيق والحوكمة]
    end

    subgraph Execution[تنفيذ معزول]
        Queue[طابور المهام]
        Workers[Workers معزولة<br/>صلاحيات دنيا · حدود موارد · قيود اتصال]
        Results[تجميع النتائج والتحقق منها]
    end

    subgraph Data[طبقة البيانات]
        PG[(PostgreSQL<br/>بيانات مؤسسات معزولة · migrations)]
        Redis[(Redis<br/>الطوابير والتنسيق المؤقت)]
        Objects[(تخزين كائنات مشفر<br/>الأدلة والتقارير)]
    end

    subgraph Operations[التشغيل والمنصة]
        Notify[الإشعارات]
        Observe[المراقبة والسجلات والتنبيهات]
        Backup[نسخ احتياطي مشفر<br/>واختبارات استعادة]
        Deploy[Docker · CI/CD<br/>Vercel · Railway عند الملاءمة]
    end

    Mobile --> Gateway
    Web --> Gateway
    Admin --> Gateway
    Gateway --> Identity
    Gateway --> Org
    Gateway --> Assets
    Gateway --> Authz
    Gateway --> Vuln
    Gateway --> Defense
    Gateway --> Forensics
    Gateway --> Threat
    Gateway --> Reports
    Gateway --> AI
    Gateway --> Billing

    Assets --> Authz
    Authz -->|تفويض صالح ونطاق مطابق فقط| Orchestrator
    Authz -.->|رفض أو انتهاء أو إلغاء| Audit
    Orchestrator --> Queue
    Queue --> Workers
    Workers --> Results
    Results --> Vuln
    Results --> Reports
    Orchestrator -->|إعادة تحقق قبل التنفيذ والإيقاف عند الإلغاء/الانتهاء| Authz

    Identity --> PG
    Org --> PG
    Assets --> PG
    Authz --> PG
    Orchestrator --> PG
    Orchestrator --> Redis
    Vuln --> PG
    Defense --> PG
    Forensics --> PG
    Forensics --> Objects
    Threat --> PG
    AI --> PG
    Reports --> Objects
    Billing --> PG
    Audit --> PG

    Gateway --> Audit
    Identity --> Audit
    Workers --> Observe
    Core --> Observe
    Execution --> Observe
    Core --> Notify
    Notify --> Clients
    PG --> Backup
    Objects --> Backup
    Deploy --> Edge
    Deploy --> Core
    Deploy --> Execution
```

## دورة المهمة الأمنية المصرح بها

```mermaid
sequenceDiagram
    actor User as المستخدم المخوّل
    participant API as API Gateway
    participant Guard as التحقق من التفويض والنطاق
    participant Orchestrator as منظّم المهام
    participant Queue as الطابور
    participant Worker as Worker معزول
    participant Store as النتائج والتدقيق

    User->>API: طلب مهمة على أصل مسجل
    API->>Guard: تحقق من المؤسسة والصلاحية والنطاق والمدة
    alt التفويض غير صالح أو النطاق غير مطابق
        Guard-->>API: رفض الطلب
        API->>Store: تسجيل الرفض في سجل التدقيق
        API-->>User: المهمة محظورة
    else التفويض صالح
        Guard-->>Orchestrator: موافقة مرتبطة بنطاق محدد
        Orchestrator->>Queue: إنشاء مهمة محدودة
        Queue->>Worker: تسليم المهمة
        Worker->>Guard: إعادة التحقق قبل التنفيذ
        alt التفويض انتهى أو أُلغي
            Guard-->>Worker: إيقاف التنفيذ
            Worker->>Store: حفظ الحالة EXPIRED أو CANCELLED والتدقيق
        else التفويض ما زال صالحاً
            Guard-->>Worker: السماح ضمن النطاق المحدد
            Worker->>Store: إرسال النتائج والأدلة
            Store-->>User: حالة المهمة والنتائج القابلة للتدقيق
        end
    end
```

## مبادئ التنفيذ

- **حاجز تفويض إلزامي:** يُفرض في API ومنظّم المهام والعامل قبل التنفيذ؛ لا تتجاوزه الواجهة أو خدمات AI.
- **عزل المؤسسات:** تُربط البيانات الحساسة بهوية المؤسسة وتُفرض ضوابط العزل في قاعدة البيانات وطبقة الخدمات.
- **تنفيذ محدود وآمن:** Workers معزولة، بصلاحيات دنيا وحدود للموارد والوقت والاتصالات، مع دعم الإلغاء.
- **أدلة موثوقة:** تُحفظ الأصول الأصلية دون تعديل، وتُسجل قيم التجزئة وسلسلة الحيازة وكل عملية وصول.
- **AI استشاري:** يحلل البيانات المصرح بها ويشرح الثقة والمصادر؛ لا يمنح تفويضاً ولا يرسل أوامر للأهداف ولا يغيّر الأدلة.
- **قابلية التدقيق والاستعادة:** تسجل العمليات الحساسة، وتُراقب الخدمات، وتُشفّر النسخ الاحتياطية وتُختبر استعادتها.

## المراحل التنفيذية

1. **Foundation:** هيكل المستودع، API، الصحة والجاهزية، نطاق التفويض، الاختبارات، Docker وCI.
2. **SaaS Core:** الهوية وMFA والمؤسسات وRBAC وعزل المستأجرين وسجلات التدقيق.
3. **Security Assessment:** الأصول والتفويض والمهام والعمال والنتائج والثغرات والتقارير.
4. **Defense & Intelligence:** الحوادث والدفاع والاستخبارات والأدلة الرقمية ومحاكاة آمنة.
5. **AI Intelligence:** تحليل وتلخيص وتوصيات استشارية مع درجات ثقة ومصادر.
6. **Applications:** تطبيق Flutter والويب ولوحة الإدارة والتصميم متعدد اللغات.
7. **Business Platform:** الخطط والاشتراكات والفوترة وحدود الاستخدام.
8. **Production:** النشر والمراقبة والنسخ الاحتياطي والاستعادة واختبارات الأمان والأداء.
