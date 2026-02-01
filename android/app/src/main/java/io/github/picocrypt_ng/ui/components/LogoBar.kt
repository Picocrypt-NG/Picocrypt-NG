package io.github.picocrypt_ng.ui.components


import androidx.compose.foundation.Image
import androidx.compose.foundation.layout.Box
import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.BlendMode
import androidx.compose.ui.graphics.ColorFilter
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import io.github.picocrypt_ng.R


@Composable
fun LogoBar() {
    Box {
        Image(
            painter = painterResource(id = R.drawable.logo_icon_nb),
            contentDescription = stringResource(R.string.logo_icon),
            colorFilter = ColorFilter.tint(MaterialTheme.colorScheme.primary, BlendMode.SrcIn)
        )
        Image(
            painter = painterResource(id = R.drawable.logo_text_nb),
            contentDescription = stringResource(R.string.logo_text)
        )
    }
}