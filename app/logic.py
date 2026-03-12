from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass
from typing import Any, Callable

from .schemas import (
    AnalyzeStrategyResponse,
    LawReference,
    LegalRequirement,
    RiskLevel,
    SeverityLevel,
    StrategyStepConfig,
    TextCheckResponse,
    ViolationMatch,
)


@dataclass(frozen=True)
class StageRule:
    """Описание правила для этапа стратегии с опциональным условием применения."""

    title: str
    requirement: str
    risk_level: RiskLevel
    recommendation: str
    law_reference: LawReference
    condition: Callable[[dict[str, Any]], bool] | None = None


_SEVERITY_ORDER: dict[SeverityLevel, int] = {
    SeverityLevel.HIGH: 0,
    SeverityLevel.MEDIUM: 1,
    SeverityLevel.LOW: 2,
}


_STAGE_ALIASES: dict[str, str] = {
    "тип продукта": "тип продукта",
    "product type": "тип продукта",
    "product-type": "тип продукта",
}


PRODUCT_TYPE_STAGE_NAME = "Тип продукта"
PRODUCT_TYPE_SETTING_KEY = "product_type"


def _normalize_stage_name(stage: str) -> str:
    """Нормализует имя этапа для устойчивого поиска правил (регистр/пробелы)."""

    normalized_spaces = " ".join(stage.strip().split())
    return normalized_spaces.casefold().replace("ё", "е")


def _risk_to_severity(risk_level: RiskLevel) -> SeverityLevel:
    """Преобразует risk_level в severity для сортировки на frontend."""

    if risk_level == RiskLevel.HIGH:
        return SeverityLevel.HIGH
    if risk_level == RiskLevel.MEDIUM:
        return SeverityLevel.MEDIUM
    return SeverityLevel.LOW


def _contains_any(settings: dict[str, Any], keys: list[str], expected_values: set[str]) -> bool:
    """Проверяет, выбран ли хотя бы один из ожидаемых пунктов в настройках блока."""

    for key in keys:
        value = settings.get(key)
        if isinstance(value, list) and expected_values.intersection({str(item).lower() for item in value}):
            return True
        if isinstance(value, str) and value.lower() in expected_values:
            return True
    return False


LEGAL_RULES_DB: dict[str, list[StageRule]] = {
    "Сбор информации": [
        StageRule(
            title="Согласие на обработку персональных данных",
            requirement="Перед сбором контактных и поведенческих данных необходимо получить информированное согласие субъекта.",
            risk_level=RiskLevel.HIGH,
            recommendation="Добавьте отдельный чекбокс согласия и ссылку на политику обработки персональных данных.",
            law_reference=LawReference(
                law='ФЗ "О персональных данных"',
                article="ст. 6, ст. 9",
                description="Обработка персональных данных допускается при наличии законных оснований, включая согласие.",
            ),
            condition=lambda settings: _contains_any(settings, ["sources"], {"опросы", "crm"}),
        ),
        StageRule(
            title="Минимизация собираемых данных",
            requirement="Собирайте только те данные, которые действительно нужны для заявленной цели маркетинга.",
            risk_level=RiskLevel.MEDIUM,
            recommendation="Уберите из формы поля, не влияющие на сегментацию или коммуникацию.",
            law_reference=LawReference(
                law='ФЗ "О персональных данных"',
                article="ст. 5",
                description="Объем и содержание данных должны соответствовать заявленным целям обработки.",
            ),
        ),
    ],
    "Анализ аудитории": [
        StageRule(
            title="Обезличивание аналитики",
            requirement="При аналитике сегментов используйте обезличенные данные, если персональная идентификация не требуется.",
            risk_level=RiskLevel.MEDIUM,
            recommendation="В отчетах исключите ФИО, телефоны, email и иные прямые идентификаторы.",
            law_reference=LawReference(
                law='ФЗ "О персональных данных"',
                article="ст. 3, ст. 5",
                description="Предусматривается возможность обработки обезличенных данных при соблюдении целей.",
            ),
        ),
        StageRule(
            title="Профилирование и автоматизированные решения",
            requirement="При использовании автоматизированного профилирования уведомляйте пользователя о логике и последствиях.",
            risk_level=RiskLevel.HIGH,
            recommendation="Добавьте в политику обработки данных раздел о профилировании и праве на возражение.",
            law_reference=LawReference(
                law='ФЗ "О персональных данных"',
                article="ст. 16",
                description="Регулируется принятие решений, порождающих юридические последствия, на основе автоматизированной обработки.",
            ),
            condition=lambda settings: settings.get("profiling") is True,
        ),
    ],
    PRODUCT_TYPE_STAGE_NAME: [
        StageRule(
            title="Ограничения рекламы 18+ товаров",
            requirement="Указывайте возрастную маркировку и исключайте обращение к несовершеннолетним в креативах.",
            risk_level=RiskLevel.HIGH,
            recommendation="Добавьте маркировку 18+ и настройте таргетинг только на совершеннолетнюю аудиторию.",
            law_reference=LawReference(
                law='ФЗ "О рекламе"',
                article="ст. 5, ст. 21",
                description="Запрещена реклама, способная причинить вред несовершеннолетним; для отдельных категорий действуют спецограничения.",
            ),
            condition=lambda settings: settings.get("product_type") == "adult",
        ),
        StageRule(
            title="Жесткие ограничения по алкоголю",
            requirement="Реклама алкогольной и подакцизной продукции ограничена по каналам, содержанию и условиям распространения.",
            risk_level=RiskLevel.HIGH,
            recommendation="Проверьте допустимость канала размещения и исключите стимулирование чрезмерного потребления.",
            law_reference=LawReference(
                law='ФЗ "О рекламе"',
                article="ст. 21",
                description="Установлены специальные запреты и ограничения для рекламы алкогольной продукции.",
            ),
            condition=lambda settings: settings.get("product_type") == "alcohol",
        ),
        StageRule(
            title="Требования к рекламе азартных игр",
            requirement="Реклама азартных игр и ставок регулируется особыми ограничениями по содержанию и времени/месту распространения.",
            risk_level=RiskLevel.HIGH,
            recommendation="Добавьте предупреждения о рисках и проверьте соответствие площадки требованиям законодательства РФ.",
            law_reference=LawReference(
                law='ФЗ "О рекламе"',
                article="ст. 27",
                description="Реклама основанных на риске игр и пари допустима только при соблюдении специальных требований.",
            ),
            condition=lambda settings: settings.get("product_type") == "gambling",
        ),
        StageRule(
            title="Корректность медицинских заявлений",
            requirement="Нельзя обещать гарантированный лечебный эффект и замену обращения к врачу.",
            risk_level=RiskLevel.HIGH,
            recommendation="Используйте нейтральные формулировки и добавляйте обязательные предупреждения, если применимо.",
            law_reference=LawReference(
                law='ФЗ "О рекламе"',
                article="ст. 24",
                description="Для рекламы медицинских услуг, изделий и лекарственных средств установлены специальные требования и запреты.",
            ),
            condition=lambda settings: settings.get("product_type") == "medical",
        ),
        StageRule(
            title="Прозрачность финансовых условий",
            requirement="В рекламе финансовых услуг должны быть раскрыты существенные условия, влияющие на доходность и стоимость.",
            risk_level=RiskLevel.HIGH,
            recommendation="Покажите полные условия, включая комиссии, диапазоны ставок и ограничения.",
            law_reference=LawReference(
                law='ФЗ "О рекламе"',
                article="ст. 28",
                description="Для финансовых услуг требуется достоверное указание существенных условий и отсутствие вводящих в заблуждение формулировок.",
            ),
            condition=lambda settings: settings.get("product_type") == "financial",
        ),
        StageRule(
            title="Осторожные формулировки для БАДов",
            requirement="Запрещено позиционировать БАДы как лекарственные средства или гарантировать лечебный эффект.",
            risk_level=RiskLevel.HIGH,
            recommendation="Используйте только допустимые формулировки о пищевой ценности и назначении без медицинских обещаний.",
            law_reference=LawReference(
                law='ФЗ "О рекламе"',
                article="ст. 25",
                description="Реклама БАДов не должна создавать впечатление, что они являются лекарством и обладают лечебными свойствами.",
            ),
            condition=lambda settings: settings.get("product_type") == "supplements",
        ),
        StageRule(
            title="Крипто-услуги: повышенный комплаенс",
            requirement="Коммуникации о крипто-сервисах должны быть максимально прозрачными и не содержать гарантий доходности.",
            risk_level=RiskLevel.HIGH,
            recommendation="Укажите риск-раскрытия и избегайте формулировок про гарантированную прибыль.",
            law_reference=LawReference(
                law='ФЗ "О рекламе"',
                article="ст. 5",
                description="Запрещены недостоверные заявления, в том числе о гарантированном результате инвестиций.",
            ),
            condition=lambda settings: settings.get("product_type") == "crypto",
        ),
        StageRule(
            title="Потребительская прозрачность цифровых продуктов",
            requirement="Для цифровых товаров важно раскрывать существенные ограничения использования, подписки и возврата.",
            risk_level=RiskLevel.MEDIUM,
            recommendation="Покажите условия лицензии, автопродления и порядок отказа/возврата до покупки.",
            law_reference=LawReference(
                law='Закон РФ "О защите прав потребителей"',
                article="ст. 10",
                description="Потребителю должна быть предоставлена достоверная и полная информация о товаре/услуге.",
            ),
            condition=lambda settings: settings.get("product_type") == "digital",
        ),
    ],
    "Выбор каналов": [
        StageRule(
            title="Маркировка рекламы",
            requirement="Рекламные материалы должны быть однозначно идентифицируемы как реклама.",
            risk_level=RiskLevel.HIGH,
            recommendation='Добавьте маркировку "Реклама" и сведения о рекламодателе на креативы.',
            law_reference=LawReference(
                law='ФЗ "О рекламе"',
                article="ст. 5, ст. 18.1",
                description="Реклама должна быть распознаваема, а распространение в интернете требует специальной маркировки.",
            ),
        ),
        StageRule(
            title="Согласие на рассылку",
            requirement="Для email/SMS/push-каналов нужно предварительное согласие адресата на получение рекламы.",
            risk_level=RiskLevel.HIGH,
            recommendation="Реализуйте double opt-in и хранение журнала согласий с датой/источником.",
            law_reference=LawReference(
                law='ФЗ "О рекламе"',
                article="ст. 18",
                description="Распространение рекламы по сетям электросвязи допускается при предварительном согласии абонента.",
            ),
            condition=lambda settings: _contains_any(settings, ["channels"], {"email", "sms", "push"}),
        ),
    ],
    "Контент-план": [
        StageRule(
            title="Недопустимость недостоверных обещаний",
            requirement="В рекламе нельзя использовать формулировки, вводящие в заблуждение о свойствах и результате продукта.",
            risk_level=RiskLevel.HIGH,
            recommendation="Замените абсолютные обещания на проверяемые и ограниченные по условиям формулировки.",
            law_reference=LawReference(
                law='ФЗ "О рекламе"',
                article="ст. 5",
                description="Недостоверная реклама, вводящая в заблуждение, запрещена.",
            ),
        ),
        StageRule(
            title="Полнота существенных условий акции",
            requirement="Если в креативе указана скидка/акция, должны быть доступны существенные условия ее получения.",
            risk_level=RiskLevel.MEDIUM,
            recommendation="Добавьте ссылку на правила акции и ограничения по срокам/категориям товаров.",
            law_reference=LawReference(
                law='ФЗ "О рекламе"',
                article="ст. 28",
                description="Реклама акций и стимулирующих мероприятий должна содержать существенные условия.",
            ),
            condition=lambda settings: settings.get("promo_campaign") is True,
        ),
    ],
}

_STAGE_RULES_BY_NORMALIZED_NAME: dict[str, list[StageRule]] = {
    _normalize_stage_name(stage_name): stage_rules
    for stage_name, stage_rules in LEGAL_RULES_DB.items()
}


_TEXT_RULES = [
    {
        "pattern": re.compile(r"гарантируем\s+результат", re.IGNORECASE),
        "explanation": "Абсолютная гарантия результата может быть признана недостоверной рекламой.",
        "suggestion": "Используйте формулировку: «Помогаем повысить вероятность результата при соблюдении условий».",
        "risk_level": RiskLevel.HIGH,
        "law_reference": LawReference(
            law='ФЗ "О рекламе"',
            article="ст. 5",
            description="Запрещена недостоверная реклама с необоснованными обещаниями.",
        ),
    },
    {
        "pattern": re.compile(r"скидка\s*70%", re.IGNORECASE),
        "explanation": "Крупная скидка без раскрытия условий может вводить потребителя в заблуждение.",
        "suggestion": "Уточните условия: «Скидка до 70% на ограниченный ассортимент по правилам акции».",
        "risk_level": RiskLevel.MEDIUM,
        "law_reference": LawReference(
            law='ФЗ "О рекламе"',
            article="ст. 28",
            description="В рекламе акций должны быть указаны существенные условия их проведения.",
        ),
    },
    {
        "pattern": re.compile(r"без\s+рисков", re.IGNORECASE),
        "explanation": "Утверждение об отсутствии рисков обычно недоказуемо и может считаться вводящим в заблуждение.",
        "suggestion": "Смягчите обещание: «Снижаем риски благодаря проверенной методологии».",
        "risk_level": RiskLevel.HIGH,
        "law_reference": LawReference(
            law='ФЗ "О рекламе"',
            article="ст. 5",
            description="Запрещены заявления, которые формируют у потребителя ложное представление.",
        ),
    },
    {
        "pattern": re.compile(r"только\s+сегодня", re.IGNORECASE),
        "explanation": "Ограничение по времени должно быть фактическим и подтверждаемым.",
        "suggestion": "Укажите точный срок: «Предложение действует до 23:59 15.09.2026».",
        "risk_level": RiskLevel.MEDIUM,
        "law_reference": LawReference(
            law='ФЗ "О рекламе"',
            article="ст. 5",
            description="Недостоверные сведения о сроках действия условий рекламы запрещены.",
        ),
    },
]

_PROFANITY_WORDS = ["fuck", "shit", "bitch", "asshole", "bastard"]
_PROFANITY_PATTERN = re.compile(
    r"\b(" + "|".join(re.escape(word) for word in _PROFANITY_WORDS) + r")\b",
    re.IGNORECASE,
)


def _resolve_stage_rules(step: StrategyStepConfig) -> list[StageRule]:
    """Ищет правила этапа по нормализованному имени, алиасам и fallback по ключам настроек."""

    normalized_name = _normalize_stage_name(step.module)
    aliased_name = _STAGE_ALIASES.get(normalized_name, normalized_name)
    stage_rules = _STAGE_RULES_BY_NORMALIZED_NAME.get(aliased_name)

    if stage_rules is not None:
        return stage_rules

    # Fallback: если фронтенд прислал другое отображаемое имя, но есть ключ product_type,
    # применяем правила модуля «Тип продукта».
    if PRODUCT_TYPE_SETTING_KEY in step.settings:
        return LEGAL_RULES_DB.get(PRODUCT_TYPE_STAGE_NAME, [])

    return []


def analyze_strategy(steps_config: list[StrategyStepConfig]) -> AnalyzeStrategyResponse:
    """Формирует правовую аналитику по текущей конфигурации маркетинговой стратегии."""

    requirements: list[LegalRequirement] = []

    for step in steps_config:
        stage_rules = _resolve_stage_rules(step)
        for rule in stage_rules:
            if rule.condition is None or rule.condition(step.settings):
                requirements.append(
                    LegalRequirement(
                        stage=step.module,
                        title=rule.title,
                        requirement=rule.requirement,
                        risk_level=rule.risk_level,
                        severity=_risk_to_severity(rule.risk_level),
                        recommendation=rule.recommendation,
                        law_reference=rule.law_reference,
                    )
                )

    requirements.sort(key=lambda item: _SEVERITY_ORDER[item.severity])

    if not requirements:
        summary = "Пока в стратегии нет активных модулей. Добавьте блоки для правового анализа."
    else:
        counters = Counter(item.risk_level for item in requirements)
        summary = (
            f"Найдено требований: {len(requirements)}. "
            f"Высокий риск: {counters.get(RiskLevel.HIGH, 0)}, "
            f"средний риск: {counters.get(RiskLevel.MEDIUM, 0)}, "
            f"безопасный уровень: {counters.get(RiskLevel.SAFE, 0)}."
        )

    return AnalyzeStrategyResponse(requirements=requirements, summary=summary)


def check_ad_text(text: str) -> TextCheckResponse:
    """Ищет рисковые рекламные формулировки и возвращает юридические комментарии."""

    violations: list[ViolationMatch] = []
    detected_words: set[str] = set()

    for rule in _TEXT_RULES:
        for match in rule["pattern"].finditer(text):
            violations.append(
                ViolationMatch(
                    phrase=match.group(0),
                    start=match.start(),
                    end=match.end(),
                    explanation=rule["explanation"],
                    suggestion=rule["suggestion"],
                    risk_level=rule["risk_level"],
                    severity=_risk_to_severity(rule["risk_level"]),
                    law_reference=rule["law_reference"],
                )
            )

    for profanity_match in _PROFANITY_PATTERN.finditer(text):
        matched_word = profanity_match.group(0)
        normalized_word = matched_word.lower()
        detected_words.add(normalized_word)

        violations.append(
            ViolationMatch(
                phrase=matched_word,
                start=profanity_match.start(),
                end=profanity_match.end(),
                explanation=(
                    "Обнаружена обсценная лексика: это повышает репутационный риск бренда и может быть оценено "
                    "как неэтичная реклама в российской практике."
                ),
                suggestion="Замените формулировку на нейтральную и профессиональную лексику без оскорбительных слов.",
                risk_level=RiskLevel.HIGH,
                severity=SeverityLevel.HIGH,
                law_reference=LawReference(
                    law='ФЗ "О рекламе"',
                    article="ст. 5",
                    description="Недобросовестная и неэтичная реклама может повлечь претензии со стороны регулятора.",
                ),
            )
        )

    violations.sort(key=lambda item: (_SEVERITY_ORDER[item.severity], item.start))

    return TextCheckResponse(
        violations=violations,
        has_violations=bool(violations),
        detected_words=sorted(detected_words),
    )
